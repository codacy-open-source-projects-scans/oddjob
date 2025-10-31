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
#include "../util.h"
#include "plain.h"

#ifndef LDAP_OPT_RESULT_CODE
#ifdef  LDAP_OPT_ERROR_NUMBER
#define LDAP_OPT_RESULT_CODE LDAP_OPT_ERROR_NUMBER
#endif
#endif

int
bind_plain(LDAP *ld,
	   const char *authn_user, const char *authz_user, const char *password)
{
	unsigned char *buffer;
	LDAPMessage *results;
	struct berval client_cred;
	int i, msgid, bind_result;
	size_t buflen;

	/* Build the authenticator. */
	buflen = 2;
	if (authz_user != NULL) {
		buflen += strlen(authz_user);
	} else {
		authz_user = "";
	}
	if (authn_user != NULL) {
		buflen += strlen(authn_user);
	} else {
		authn_user = "";
	}
	if (password != NULL) {
		buflen += strlen(password);
	} else {
		password = "";
	}
	buffer = malloc(buflen + 1);
	if (buffer == NULL) {
		printf("Out of memory before sending "
		       "PLAIN sasl_bind request!\n");
		return -1;
	}
	memcpy(buffer,
	       authz_user, strlen(authz_user) + 1);
	memcpy(buffer + strlen(authz_user) + 1,
	       authn_user, strlen(authn_user) + 1);
	memcpy(buffer + strlen(authz_user) + 1 + strlen(authn_user) + 1,
	       password, strlen(password) + 1);
	client_cred.bv_val = buffer;
	client_cred.bv_len = buflen;
	/* Take whatever client data we have and send it to the
 	 * server. */
	i = ldap_sasl_bind(ld, NULL, "PLAIN", &client_cred,
			   NULL, NULL, &msgid);
	free(buffer);
	if (i != LDAP_SUCCESS) {
		printf("Error sending PLAIN sasl_bind request to "
		       "the server!\n");
		return -1;
	}

	/* Wait for a result message for this bind request. */
	results = NULL;
	i = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &results);
	if (i != LDAP_RES_BIND) {
		printf("Error while waiting for response to "
		       "PLAIN sasl_bind request (%d)!\n", i);
		return -1;
	}

	/* Retrieve the result code for the bind request. */
	i = ldap_parse_sasl_bind_result(ld, results, NULL, 0);
	ldap_msgfree(results);

	/* Okay, here's where things get tricky.  Both Mozilla's LDAP SDK and
	 * OpenLDAP store the result code which was returned by the server in
	 * the handle's ERROR_NUMBER option.  Mozilla returns LDAP_SUCCESS if
	 * the data was parsed correctly, even if the result was an error,
	 * while OpenLDAP returns the result code.  I lean toward Mozilla being
	 * correct. */
	if (i == LDAP_SUCCESS) {
		/* Mozilla? */
		if (ldap_get_option(ld, LDAP_OPT_RESULT_CODE,
				    &bind_result) != LDAP_SUCCESS) {
			printf("Error retrieving response to "
			       "PLAIN sasl_bind request!\n");
		}
	} else {
		/* OpenLDAP? */
		switch (i) {
		case LDAP_SUCCESS:
		case LDAP_SASL_BIND_IN_PROGRESS:
		case LDAP_AUTH_METHOD_NOT_SUPPORTED:
		case LDAP_STRONG_AUTH_REQUIRED:
		case LDAP_INVALID_CREDENTIALS:
			bind_result = i;
			break;
		default:
			printf("Error parsing response to "
			       "PLAIN sasl_bind request (%d)!\n", i);
			break;
		}
	}

	return (bind_result == LDAP_SUCCESS) ? 0 : -1;
}
