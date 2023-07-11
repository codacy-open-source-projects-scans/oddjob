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
#include "scrape.h"
#include "common.h"

struct globals globals;

int
main(int argc, char **argv)
{
	int i;
	char *p, key[LINE_MAX];

	scrape_smbconf("global/password server", &globals.domain_controller[0],
		       sizeof(globals.domain_controller),
		       "global/workgroup", &globals.workgroup[0],
		       sizeof(globals.workgroup),
		       "global/realm", &globals.realm[0],
		       sizeof(globals.realm),
		       "global/netbios name", &globals.machine_name[0],
		       sizeof(globals.machine_name),
		       NULL);
	snprintf(key, sizeof(key), "SECRETS/MACHINE_PASSWORD/%s",
		 globals.workgroup);
	scrape_tdb(PATH_SECRETS,
		   key, &globals.machine_password[0],
		   sizeof(globals.machine_password),
		   NULL);
	printf("domain_controller: %s\n", globals.domain_controller);
	printf("workgroup: %s\n", globals.workgroup);
	printf("realm: %s\n", globals.realm);
	printf("my name: %s\n", globals.machine_name);
	printf("my password: %s\n", globals.machine_password);
	i = lookup_ads_init(NULL);
	if (i != 0) {
		printf("error initializing lookup, continuing anyway\n");
	}
	for (i = 1; i + 1 < argc; i += 2) {
		p = lookup_ads_lookup(argv[i], argv[i + 1]);
		printf("%s.%s: %s\n", argv[i], argv[i + 1], p);
		lookup_ads_free_result(p);
	}
	lookup_ads_done();
	return 0;
}

