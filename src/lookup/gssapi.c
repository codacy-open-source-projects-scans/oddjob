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
#include <gssapi/gssapi.h>
#if defined(HAVE_ET_COM_ERR_H)
#include <et/com_err.h>
#elif defined(HAVE_COM_ERR_H)
#include <com_err.h>
#endif
#include "../util.h"
#include "gssapi.h"

#ifndef LDAP_OPT_RESULT_CODE
#ifdef  LDAP_OPT_ERROR_NUMBER
#define LDAP_OPT_RESULT_CODE LDAP_OPT_ERROR_NUMBER
#endif
#endif

int
bind_gssapi(LDAP *ld, const char *myname, const char *servername)
{
	gss_ctx_id_t context;
	OM_uint32 init_major, major, minor, flags, time_rec;
	gss_cred_id_t creds;
	gss_buffer_desc input_name, input_token, output_token;
	gss_name_t client_name, server_name;
	gss_OID mech_oid;
	gss_OID_set mech_oids, supported_oids;
	int i, msgid, sasl_result, bind_result, authenticated;
	unsigned int oid;
	struct berval client_cred, *server_cred, temp_cred;
	LDAPMessage *results, *entry;

	/* Import the service name for use as a GSSAPI name. */
	input_name.length = strlen("ldap@") + strlen(servername);
	input_name.value = malloc(input_name.length + 1);
	if (input_name.value == NULL) {
		return -1;
	}
	sprintf(input_name.value, "ldap@%s", servername);
	server_name = GSS_C_NO_NAME;
	major = gss_import_name(&minor, &input_name, GSS_C_NT_HOSTBASED_SERVICE,
				&server_name);
	if (major != GSS_S_COMPLETE) {
		printf("import_name(ldap@%s,1): %x\n", servername, major);
		return -1;
	}
	printf("import_name(ldap@%s,1): %x\n", servername, major);
	free(input_name.value);

#if 1
	/* Figure out who we are. */
	input_name.length = strlen(myname);
	input_name.value = malloc(input_name.length + 1);
	if (input_name.value == NULL) {
		return -1;
	}
	sprintf(input_name.value, "%s", myname);
	client_name = GSS_C_NO_NAME;
	major = gss_import_name(&minor, &input_name, GSS_C_NT_USER_NAME,
				&client_name);
	free(input_name.value);
	if (major != GSS_S_COMPLETE) {
		printf("import_name(2): %x\n", major);
		return -1;
	}
#else
	client_name = GSS_C_NO_NAME;
#endif

	/* Get a list of supported mechanisms. */
	supported_oids = GSS_C_NO_OID_SET;
	major = gss_indicate_mechs(&minor, &supported_oids);
	if (major != GSS_S_COMPLETE) {
		printf("indicate_mechs: %x\n", major);
		return -1;
	}

	/* Get the credentials. */
	creds = GSS_C_NO_CREDENTIAL;
	mech_oids = GSS_C_NO_OID_SET;
	major = gss_acquire_cred(&minor, &client_name, GSS_C_INDEFINITE,
				 supported_oids, GSS_C_INITIATE,
				 &creds, &mech_oids, &time_rec);
	if (major != GSS_S_COMPLETE) {
		printf("acquire_cred: %x/%x: %s\n", major, minor,
		       error_message(minor));
		return -1;
	}

	for (oid = 0; (mech_oids != NULL) && (oid < mech_oids->count); oid++) {
		/* Create a new authentication context for the service and
		 * obtain the initial token. */
		context = GSS_C_NO_CONTEXT;
		mech_oid = GSS_C_NO_OID;
		major = gss_init_sec_context(&minor, &creds,
					     &context, server_name,
					     &mech_oids->elements[oid],
					     GSS_C_MUTUAL_FLAG,
					     GSS_C_INDEFINITE,
					     GSS_C_NO_CHANNEL_BINDINGS,
					     GSS_C_NO_BUFFER,
					     &mech_oid,
					     &output_token,
					     &flags,
					     &time_rec);
		init_major = major;
		if ((init_major != GSS_S_COMPLETE) &&
		    ((init_major & GSS_S_CONTINUE_NEEDED) == 0)) {
			gss_release_name(&minor, server_name);
			printf("bad name %x/%x: %s\n", major, minor,
			       error_message(minor));
			return -1;
		}

		do {
			/* Take whatever client data we have and send it to the
			 * server. */
			client_cred.bv_val = output_token.value;
			client_cred.bv_len = output_token.length;
			i = ldap_sasl_bind(ld, NULL, "GSSAPI", &client_cred,
					   NULL, NULL, &msgid);
			if (i != LDAP_SUCCESS) {
				printf("Error sending GSSAPI sasl_bind request "
				       "to the server!\n");
				gss_release_name(&minor, server_name);
				return -1;
			}

			/* Wait for a result message for this bind request. */
			results = NULL;
			i = ldap_result(ld, msgid, LDAP_MSG_ALL,
					NULL, &results);
			if (i != LDAP_RES_BIND) {
				printf("Error while waiting for response to "
				       "GSSAPI sasl_bind request!\n");
				gss_release_name(&minor, server_name);
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
			 * the result code. */
			if (i == LDAP_SUCCESS) {
				/* Mozilla? */
				if (ldap_get_option(ld, LDAP_OPT_RESULT_CODE,
						    &bind_result) != LDAP_SUCCESS) {
					printf("Error retrieving response to "
					       "GSSAPI sasl_bind request!\n");
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
					       "GSSAPI sasl_bind request!\n");
					break;
				}
			}

			/* If the server sent us something, then we'd better be
			 * expecting it. */
			i = ((server_cred != NULL) && 
			     (server_cred->bv_len > 0)) -
			    (((init_major & GSS_S_CONTINUE_NEEDED) != 0));
			if (i != 0) {
				if ((init_major & GSS_S_CONTINUE_NEEDED) == 0) {
					printf("Server sent us response data, "
					       "but we thought we were done!"
					       "\n");
				} else {
					printf("Server did not send us any "
					       "data, but we needed some!\n");
				}
				break;
			}

			printf("%d\n", __LINE__);

			/* If we need another round trip, process whatever we
			 * received and prepare data to be transmitted back. */
			if (((init_major & GSS_S_CONTINUE_NEEDED) != 0) &&
			    ((bind_result == LDAP_SUCCESS) ||
			     (bind_result == LDAP_SASL_BIND_IN_PROGRESS))) {
				if (server_cred != NULL) {
					input_token.value = server_cred->bv_val;
					input_token.length = server_cred->bv_len;
				} else {
					input_token.value = NULL;
					input_token.length = 0;
				}
				major = gss_init_sec_context(&minor, &creds,
							     &context, server_name,
							     mech_oid,
							     GSS_C_MUTUAL_FLAG,
							     0,
							     GSS_C_NO_CHANNEL_BINDINGS,
							     &input_token,
							     &mech_oid,
							     &output_token,
							     &flags,
							     &time_rec);
				init_major = major;
				/* If we have data to send, then the server had
				 * better be expecting it.  (It's valid to send
				 * the server no data with a request.) */
				if (((major & GSS_S_CONTINUE_NEEDED) != 0) &&
				    (bind_result != LDAP_SASL_BIND_IN_PROGRESS)) {
					printf("We have data for the server, "
					       "but it thinks we are done!\n");
					break;
				}
			}
			/* If the server says we succeeded, and the client
			 * library says we succeeded, then we're done. */
			if ((init_major == GSS_S_COMPLETE) &&
			    (bind_result == LDAP_SUCCESS)) {
				authenticated++;
			}
		} while ((init_major & GSS_S_CONTINUE_NEEDED) != 0);
		gss_delete_sec_context(&minor, &context, &output_token);
	}
	gss_release_name(&minor, server_name);
	return (authenticated > 0) ? 0 : -1;
}
