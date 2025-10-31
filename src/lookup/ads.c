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
#include <krb5.h>
#include <ldap.h>
#include "../util.h"
#include "cyrus.h"
#include "gssapi.h"
#include "plain.h"
#include "scrape.h"
#include "common.h"

extern struct globals globals;

#ifndef LDAP_OPT_RESULT_CODE
#ifdef  LDAP_OPT_ERROR_NUMBER
#define LDAP_OPT_RESULT_CODE LDAP_OPT_ERROR_NUMBER
#endif
#endif

void
lookup_ads_cleanup(void)
{
	if (globals.ld) {
		ldap_unbind(globals.ld);
	}
	globals.ld = NULL;
	if (globals.ccache && globals.ctx) {
		krb5_cc_destroy(globals.ctx, globals.ccache);
	}
	globals.ccache = NULL;
	if (globals.ctx) {
		krb5_free_context(globals.ctx);
	}
	globals.ctx = NULL;
	memset(&globals, 0, sizeof(globals));
}

int
lookup_ads_init(const char *detail)
{
	int i;
	krb5_principal princ;
	krb5_creds creds;
	char principal[sizeof(globals.machine_name) + sizeof(globals.realm) + 2];

	putenv("KRB5CCNAME=MEMORY:_krb5_cc_lookup_ads");

	globals.ctx = NULL;
	if ((i = krb5_init_context(&globals.ctx)) != 0) {
		lookup_ads_cleanup();
		return i;
	}
	globals.ccache = NULL;
	if ((i = krb5_cc_default(globals.ctx, &globals.ccache)) != 0) {
		lookup_ads_cleanup();
		return i;
	}
	princ = NULL;
	sprintf(principal, "%s@%s", globals.machine_name, globals.realm);
	if ((i = krb5_parse_name(globals.ctx, principal, &princ)) != 0) {
		lookup_ads_cleanup();
		return i;
	}
	if ((i = krb5_cc_initialize(globals.ctx, globals.ccache, princ) != 0)) {
		lookup_ads_cleanup();
		return i;
	}
	memset(&creds, 0, sizeof(creds));
	if ((i = krb5_get_init_creds_password(globals.ctx,
					      &creds,
					      princ,
					      globals.machine_password,
					      NULL,
					      NULL,
					      0,
					      NULL,
					      NULL)) != 0) {
		lookup_ads_cleanup();
		return i;
	}
	if (krb5_cc_store_cred(globals.ctx, globals.ccache, &creds) != 0) {
		krb5_free_cred_contents(globals.ctx, &creds);
		lookup_ads_cleanup();
		return i;
	}
	krb5_free_cred_contents(globals.ctx, &creds);

	return 0;
}

char **
lookup_ads_search_text(LDAP *ld, const char *base, int scope,
		       const char *attribute, const char *filterfmt, ...)
{
	char filter[LINE_MAX];
	va_list args;
	LDAPMessage *results, *e;
	int count, i;
	const char *attributes[2];
	char **ret, **values, *dn;

	if ((filterfmt != NULL) && (strlen(filterfmt) > 0)) {
		va_start(args, filterfmt);
		vsnprintf(filter, sizeof(filter), filterfmt, args);
		va_end(args);
	} else {
		strcpy(filter, "");
	}

	results = NULL;
	attributes[0] = attribute;
	attributes[1] = NULL;
	if ((i = ldap_search_ext_s(ld, base, scope,
			           strlen(filter) ? filter : "(objectclass=*)",
			           (char**) attributes, 0,
				   NULL, NULL,
				   NULL, LDAP_NO_LIMIT,
				   &results)) != LDAP_SUCCESS) {
		char *msg;
		int error;
		if (ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER,
				    &error) != LDAP_SUCCESS) {
			error = i;
		}
		if (ldap_get_option(ld, LDAP_OPT_ERROR_STRING,
				    &msg) != LDAP_SUCCESS) {
			msg = "";
		}
		if (results == NULL) {
			return NULL;
		}
	}

	ret = NULL;
	count = 0;
	for (e = ldap_first_entry(ld, results);
	     e != NULL;
	     e = ldap_next_entry(ld, e)) {
		dn = ldap_get_dn(ld, e);
		if (dn != NULL) {
			ldap_memfree(dn);
		}
		values = ldap_get_values(ld, e, attribute);
		if (values != NULL) {
			oddjob_resize_array((void**) &ret, sizeof(char*),
					    count,
					    count +
					    ldap_count_values(values) +
					    1);
			for (i = 0; i < ldap_count_values(values); i++) {
				ret[count + i] = oddjob_strdup(values[i]);
			}
			count += ldap_count_values(values);
		}
	}

	ldap_msgfree(e);

	return ret;
}

void
lookup_ads_search_free(char **values)
{
	oddjob_freev(values);
}

char *
lookup_ads_lookup(const char *user, const char *attribute)
{
	int i, j, version, referrals_set, attempt;
	LDAPControl *serverControls, *clientControls;
	char **namingcontexts, **values, *ret, *hostname, host[LINE_MAX];
	void *referrals_requested;

	globals.ld = ldap_init(globals.domain_controller, LDAP_PORT);
	if (globals.ld == NULL) {
		return NULL;
	}
	serverControls = clientControls = NULL;
	if (ldap_get_option(globals.ld,
			    LDAP_OPT_PROTOCOL_VERSION,
			    &version) == 0) {
		if (version < 3) {
			version = 3;
			if (ldap_set_option(globals.ld,
					    LDAP_OPT_PROTOCOL_VERSION,
					    &version) != 0) {
				ldap_unbind(globals.ld);
				globals.ld = NULL;
				return NULL;
			}
		}
	}
	if (ldap_get_option(globals.ld,
			    LDAP_OPT_REFERRALS,
			    &referrals_set) == 0) {
		if (referrals_set != 0) {
			referrals_requested = LDAP_OPT_OFF;
			if (ldap_set_option(globals.ld,
					    LDAP_OPT_REFERRALS,
					    referrals_requested) != 0) {
			}
		}
	}
	values = lookup_ads_search_text(globals.ld,
					"",
					LDAP_SCOPE_BASE,
					"dnsHostName",
					NULL);
	if ((values != NULL) && (values[0] != NULL)) {
		snprintf(host, sizeof(host), "%s", values[0]);
	} else {
		if (ldap_get_option(globals.ld,
				    LDAP_OPT_HOST_NAME,
				    &hostname) == 0) {
			snprintf(host, sizeof(host), "%s", hostname);
		} else {
			snprintf(host, sizeof(host), "%s",
				 globals.domain_controller);
		}
	}
	if (values != NULL) {
		lookup_ads_search_free(values);
	}
#if 0
	if ((i = bind_cyrus_sasl(globals.ld, host)) != 0) {
		ldap_unbind(globals.ld);
		globals.ld = NULL;
		return NULL;
	}
#elif 1
	if ((i = bind_gssapi(globals.ld, globals.machine_name,
			     host)) != 0) {
		ldap_unbind(globals.ld);
		globals.ld = NULL;
		return NULL;
	}
#else
	if ((i = bind_plain(globals.ld,
			    globals.machine_name,
			    NULL,
			    globals.machine_password)) != 0) {
		ldap_unbind(globals.ld);
		globals.ld = NULL;
		return NULL;
	}
#endif
	namingcontexts = lookup_ads_search_text(globals.ld,
						"",
						LDAP_SCOPE_BASE,
						"namingcontexts",
						NULL);
	ret = NULL;
	for (i = 0;
	     (ret == NULL) &&
	     (namingcontexts != NULL) &&
	     (namingcontexts[i] != NULL);
	     i++) {
		values = lookup_ads_search_text(globals.ld,
						namingcontexts[i],
						LDAP_SCOPE_SUBTREE,
						attribute,
						"(&"
						"(objectcategory=user)"
						"(samaccountname=%s)"
						")",
						user);
		for (j = 0; (values != NULL) && (values[j] != NULL); j++) {
			ret = oddjob_strdup(values[j]);
			break;
		}
		lookup_ads_search_free(values);
	}
	lookup_ads_search_free(namingcontexts);
	ldap_unbind(globals.ld);
	globals.ld = NULL;
	return ret;
}

void
lookup_ads_free_result(char *tofree)
{
	oddjob_free(tofree);
}

int
lookup_ads_done(void)
{
	lookup_ads_cleanup();
	return 0;
}
