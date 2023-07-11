/*
   Copyright 2005 Red Hat, Inc.
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Red Hat, Inc., nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
   TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
   PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
   OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../../config.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include "../util.h"
#include "cyrus.h"

#ifndef LDAP_OPT_RESULT_CODE
#ifdef  LDAP_OPT_ERROR_NUMBER
#define LDAP_OPT_RESULT_CODE LDAP_OPT_ERROR_NUMBER
#endif
#endif

int
bind_cyrus_sasl(LDAP *ld, const char *servername)
{
	sasl_conn_t *conn;
	int i, authenticated, msgid, sasl_result, bind_result;
	unsigned int mech_index;
	char **mechanisms;
	const char *clientout, *chosen_mech;
	unsigned int clientoutlen;
	struct berval client_cred, *server_cred, temp_cred;
	LDAPMessage *results, *entry;
	const char *saslattrlist[] = {"supportedSASLmechanisms", NULL};

	results = NULL;
	i = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE, "(objectclass=*)",
			      (char **)saslattrlist, 0,
			      NULL, NULL,
			      NULL, LDAP_NO_LIMIT, &results);
	if (i != LDAP_SUCCESS) {
		/* Well, we're screwed now. */
		return -1;
	}
	entry = ldap_first_entry(ld, results);
	if (entry == NULL) {
		/* No root DSE. (!) */
		ldap_msgfree(results);
		return -1;
	}

	mechanisms = ldap_get_values(ld, entry, "supportedSASLmechanisms");
	ldap_msgfree(results);
	if (mechanisms == NULL) {
		/* Well, that was a waste of time. */
		return -1;
	}

	/* Start up Cyrus SASL.  Only needs to be done once, but we don't check
 	 * on that for now. */
	if (sasl_client_init(NULL) != SASL_OK) {
		ldap_value_free(mechanisms);
		return -1;
	}

	/* Create a new authentication context for the service. */
	if (sasl_client_new("ldap", servername,
			    NULL, NULL, NULL, 0, &conn) != SASL_OK) {
		ldap_value_free(mechanisms);
		return -1;
	}

	/* Try each supported mechanism in turn. */
	for (mech_index = 0, authenticated = 0;
	     (mechanisms[mech_index] != NULL) && (authenticated == 0);
	     mech_index++) {
		/* First step. */
		chosen_mech = NULL;
		sasl_result = sasl_client_start(conn, mechanisms[mech_index],
						NULL,
						&clientout, &clientoutlen,
						&chosen_mech);

		/* OK and CONTINUE are the only non-fatal return codes here. */
		if ((sasl_result != SASL_OK) &&
		    (sasl_result != SASL_CONTINUE)) {
			continue;
		}

		do {
			/* Take whatever client data we have and send it to the
 			 * server. */
			client_cred.bv_val = (unsigned char *) clientout;
			client_cred.bv_len = clientoutlen;
			i = ldap_sasl_bind(ld, NULL, chosen_mech,
					   (client_cred.bv_len > 0) ?
					   &client_cred : NULL,
					   NULL, NULL, &msgid);
			if (i != LDAP_SUCCESS) {
				printf("Error sending sasl_bind request to "
				       "the server!\n");
				ldap_value_free(mechanisms);
				return -1;
			}

			/* Wait for a result message for this bind request. */
			results = NULL;
			i = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL,
					&results);
			if (i != LDAP_RES_BIND) {
				printf("Error while waiting for response to "
				       "sasl_bind request!\n");
				ldap_value_free(mechanisms);
				return -1;
			}

			/* Retrieve the result code for the bind request and
 			 * any data which the server sent. */
			server_cred = NULL;
			i = ldap_parse_sasl_bind_result(ld, results,
							&server_cred, 0);
			ldap_msgfree(results);

			/* Okay, here's where things get tricky.  Both
			 * Mozilla's LDAP SDK and OpenLDAP store the result
			 * code which was returned by the server in the
			 * handle's ERROR_NUMBER option.  Mozilla returns
			 * LDAP_SUCCESS if the data was parsed correctly, even
			 * if the result was an error, while OpenLDAP returns
			 * the result code.  I'm leaning toward Mozilla being
			 * more correct. */
			if (i == LDAP_SUCCESS) {
				/* Mozilla? */
				if (ldap_get_option(ld, LDAP_OPT_RESULT_CODE,
						    &bind_result) != LDAP_SUCCESS) {
					printf("Error retrieving response to "
					       "sasl_bind request!\n");
					break;
				}
			} else {
				/* OpenLDAP? */
				switch (i) {
				case LDAP_SUCCESS:
				case LDAP_SASL_BIND_IN_PROGRESS:
					bind_result = i;
					break;
				default:
					printf("Error parsing response to "
					       "sasl_bind request!\n");
					break;
				}
			}

			/* If the server sent us something, then we'd better be
			 * expecting it. */
			i = ((server_cred != NULL) && 
			     (server_cred->bv_len > 0)) -
			    (sasl_result == SASL_CONTINUE);
			if (i != 0) {
				if (sasl_result != SASL_CONTINUE) {
					printf("Server sent us response data, "
					       "but we thought we were done!"
					       "\n");
				} else {
					printf("Server did not send us any "
					       "data, but we needed some!\n");
				}
				break;
			}

			/* If we need another round trip, process whatever we
 			 * received and prepare data to be transmitted back. */
			if ((sasl_result == SASL_CONTINUE) &&
			    ((bind_result == LDAP_SUCCESS) ||
			     (bind_result == LDAP_SASL_BIND_IN_PROGRESS))) {
				if (server_cred != NULL) {
					temp_cred = *server_cred;
				} else {
					temp_cred.bv_len = 0;
					temp_cred.bv_val = NULL;
				}
				sasl_result = sasl_client_step(conn,
							       temp_cred.bv_val,
							       temp_cred.bv_len,
							       NULL,
							       &clientout,
							       &clientoutlen);
				/* If we have data to send, then the server
				 * had better be expecting it.  (It's valid
				 * to send the server no data with a request.)
				 */
				if ((clientoutlen > 0) &&
				    (bind_result != LDAP_SASL_BIND_IN_PROGRESS)) {
					printf("We have data for the server, "
					       "but it thinks we are done!\n");
					break;
				}
			}
			/* If the server says we succeeded, and the client
 			 * library says we succeeded, then we're done. */
			if ((sasl_result == SASL_OK) &&
			    (bind_result == LDAP_SUCCESS)) {
				authenticated++;
			}
		} while ((bind_result == LDAP_SASL_BIND_IN_PROGRESS) ||
			 (sasl_result == SASL_CONTINUE));
	}
	sasl_dispose(&conn);
	ldap_value_free(mechanisms);
	return (authenticated > 0) ? 0 : -1;
}
