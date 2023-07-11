/*
   Copyright 2005,2006 Red Hat, Inc.
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

#include "../config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <dbus/dbus.h>
#include "handlers.h"
#include "util.h"

static int
run(const char *service, const char *command)
{
	pid_t pid;
	int exec_status[2], daemon_status[2];
	char **argv;
	const char *error, *argv0;
	char c;
	int i;

	error = NULL;
	argv = oddjob_parse_args(command, &error);
	if (argv == NULL) {
		fprintf(stderr, "Error starting \"%s\": %s",
			service, error ? error : "Unknown error");
		return 1;
	}
	printf("Trying to start \"%s\" service (", service);
	for (i = 0; argv[i] != NULL; i++) {
		printf("%s\"%s\"", i > 0 ? ", " : "", argv[i]);
	}
	printf(")\n");

	/* Create two status pipes. */
	if (pipe(exec_status) != 0) {
		fprintf(stderr, "Error at pipe(): %s\n", strerror(errno));
		return 1;
	}
	if (pipe(daemon_status) != 0) {
		fprintf(stderr, "Error at pipe(): %s\n", strerror(errno));
		close(exec_status[0]);
		close(exec_status[1]);
		return 1;
	}
	if (fcntl(exec_status[1], F_SETFD, FD_CLOEXEC) != 0) {
		fprintf(stderr, "Error at fcntl(): %s\n", strerror(errno));
		close(exec_status[0]);
		close(exec_status[1]);
		close(daemon_status[0]);
		close(daemon_status[1]);
		return 1;
	}
	if (fcntl(daemon_status[1], F_SETFD, FD_CLOEXEC) != 0) {
		fprintf(stderr, "Error at fcntl(): %s\n", strerror(errno));
		close(exec_status[0]);
		close(exec_status[1]);
		close(daemon_status[0]);
		close(daemon_status[1]);
		return 1;
	}

	/* Fork a child to start the new daemon. */
	pid = fork();
	switch (pid) {
	case -1:
		fprintf(stderr, "Error at fork(): %s\n", strerror(errno));
		close(daemon_status[0]);
		close(daemon_status[1]);
		close(exec_status[0]);
		close(exec_status[1]);
		break;
	default:
		/* we are the child, close the read ends and continue */
		close(exec_status[0]);
		close(daemon_status[0]);
		/* if we can't detach, notify of error */
		if (daemon(0, 0) != 0) {
			c = errno;
			write(daemon_status[1], &c, 1);
			_exit(1);
		}
		close(daemon_status[1]);
		/* if we can't exec, notify of error */
		argv0 = argv[0];
		if (strchr(argv0, '/') != NULL) {
			argv0 = strrchr(argv0, '/') + 1;
		}
		execvp(argv0, argv);
		c = errno;
		write(exec_status[1], &c, 1);
		_exit(1);
		break;
	case 0:
		/* we are the parent, close the write ends */
		close(exec_status[1]);
		close(daemon_status[1]);
		/* read the daemon() result */
		if (read(daemon_status[0], &c, 1) == 1) {
			close(daemon_status[0]);
			fprintf(stderr, "Error at daemon(): %s\n", strerror(c));
			close(exec_status[0]);
			_exit(1);
		}
		close(daemon_status[0]);
		/* read the daemon() result */
		if (read(exec_status[0], &c, 1) == 1) {
			close(exec_status[0]);
			fprintf(stderr, "Error at exec(): %s\n", strerror(c));
			_exit(1);
		}
		/* good to go! */
		break;
	}
	return 0;
}

/* Given a service name, scan the .desktop files and locate the binary which
 * should implement that service. */
static int
launch(const char *service)
{
	glob_t globbed;
	char command[PATH_MAX + 1], names[8192], buf[8192], *p;
	struct {
		const char key[7];
		size_t keylen;
		char *buf;
		size_t bufsize;
	} vars[] = {
		{"Names=", sizeof("Names=") - 1, names, sizeof(names)},
		{"Name=", sizeof("Name=") - 1, names, sizeof(names)},
		{"Exec=", sizeof("Exec=") - 1, command, sizeof(command)},
	};
	FILE *fp;
	unsigned i, j, span;
	const char *section1 = "[D-BUS Service]", *section2 = "[D-Bus Service]";
	dbus_bool_t found, in_section, dupe;

	i = glob(DATADIR "/" DBUS_PACKAGE "/services/*.service",
		 0, NULL, &globbed);
	if (i != 0) {
		return -1;
	}

	found = dupe = FALSE;
	for (i = 0; i < globbed.gl_pathc; i++) {
		in_section = FALSE;
		fp = fopen(globbed.gl_pathv[i], "r");
		if (fp != NULL) {
			strcpy(command, "");
			strcpy(names, "");
			while (fgets(buf, sizeof(buf), fp) != NULL) {
				/* If it looks like a section start, check if
				 * it's the section we need to heed. */
				if (buf[0] == '[') {
					in_section = (((strncmp(buf, section1,
							        strlen(section1)) == 0) &&
						       (strchr("\r\n",
							       buf[strlen(section1)]) != NULL)) ||
						      ((strncmp(buf, section2,
							        strlen(section2)) == 0) &&
						       (strchr("\r\n",
							       buf[strlen(section2)]) != NULL)));
					continue;
				}
				if (!in_section) {
					continue;
				}
				/* Parse out variables about which we care. */
				for (j = 0;
				     j < sizeof(vars) / sizeof(vars[0]);
				     j++) {
					if (vars[j].keylen <= 0) {
						vars[j].keylen =
							strlen(vars[j].key);
					}
					if (strncmp(buf, vars[j].key,
						    vars[j].keylen) == 0) {
						snprintf(vars[j].buf,
							 vars[j].bufsize,
							 "%s",
							 buf + vars[j].keylen);
						/* Snip of trailing CR/LFs. */
						span = strcspn(vars[j].buf,
							       "\r\n");
						if (span > 0) {
							vars[j].buf[span] = '\0';
						}
						break;
					}
				}
			}
			/* If we got a path and names, check if we have a match
			 * on the service name. */
			if ((strlen(command) > 0) && (strlen(names) > 0)) {
				p = names;
				while (*p == ';') {
					p++;
				}
				while (*p != '\0') {
					span = strcspn(p, ";\r\n");
					if (span > 0) {
						if (strncmp(service, p,
							    span) == 0) {
							if (found) {
								/* Duplicate! */
								dupe = TRUE;
							}
							found = TRUE;
							break;
						}
					}
					p += span;
					p += strspn(p, ";\r\n");
				}
			}
			fclose(fp);
		}
	}
	globfree(&globbed);
	/* If we got a match, run it. */
	if (found && !dupe) {
		return run(service, command);
	}
	return HANDLER_FAILURE;
}

int
main(int argc, char **argv)
{
	char arg[LINE_MAX];
	int i;
	openlog(PACKAGE "-dbus-launch", LOG_PID, LOG_DAEMON);
	if (fgets(arg, sizeof(arg), stdin) != NULL) {
		i = strcspn(arg, "\r\n");
		arg[i] = '\0';
		if (strlen(arg) > 0) {
			i = launch(arg);
			closelog();
			return i;
		}
	}
	closelog();
	return HANDLER_INVALID_INVOCATION;
}
