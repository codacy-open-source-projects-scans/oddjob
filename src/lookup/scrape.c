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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include "../util.h"
#include "scrape.h"

#define WHITESPACE " \t"
#define NEWLINES   "\r\n"

struct scrape_arg {
	const char *key;
	char *buf;
	size_t buflen;
};

void
scrape_smbconf(const char *directive, ...)
{
	pid_t pid;
	int pipefd[2], fd;
	unsigned int i;
	FILE *fp;
	char *line, *q, *section;
	const char *p;
	size_t n, n_args;
	va_list args;
	struct scrape_arg *scrape_args;

	if (directive == NULL) {
		return;
	}

	va_start(args, directive);
	n = 0;
	do {
		p = va_arg(args, char*);
		i = va_arg(args, size_t);
		n++;
	} while ((p = va_arg(args, const char*)) != NULL);
	va_end(args);

	n_args = n;
	scrape_args = NULL;
	oddjob_resize_array((void **)&scrape_args, sizeof(scrape_args[0]),
			    0, n_args);

	va_start(args, directive);
	scrape_args[0].key = directive;
	scrape_args[0].buf = va_arg(args, char*);
	scrape_args[0].buflen = va_arg(args, size_t);
	for (n = 1; n < n_args; n++) {
		scrape_args[n].key = va_arg(args, const char*);
		scrape_args[n].buf = va_arg(args, char*);
		scrape_args[n].buflen = va_arg(args, size_t);
	}
	va_end(args);

	if (pipe(pipefd) == -1) {
		free(scrape_args);
		return;
	}
	pid = fork();
	switch (pid) {
	case -1:
		close(pipefd[0]);
		close(pipefd[1]);
		free(scrape_args);
		return;
	case 0:
		for (fd = 0; fd < sysconf(_SC_OPEN_MAX); fd++) {
			if (fd != pipefd[1]) {
				close(fd);
			}
		}
		if (pipefd[1] != STDOUT_FILENO) {
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[1]);
		}
		execl(PATH_TESTPARM, PATH_TESTPARM, "-sv", NULL);
		_exit(1);
		break;
	default:
		close(pipefd[1]);
		fp = fdopen(pipefd[0], "r");
		if (fp != NULL) {
			line = NULL;
			n = 0;
			section = NULL;
			while (getline(&line, &n, fp) != -1) {
				/* Check if this is a section start. */
				q = line + strspn(line, WHITESPACE);
				if (*q == '[') {
					free(section);
					section = strdup(q + 1);
					q = section + strcspn(section, "]");
					*q = '\0';
					continue;
				}
				/* If we're not in a section yet, then ignore
				 * whatever this line is. */
				if (section == NULL) {
					continue;
				}
				/* Iterate over each key we were given. */
				for (i = 0; i < n_args; i++) {
					p = scrape_args[i].key;
					p += strspn(p, WHITESPACE);
					/* Check if this is the right section.
					 * for the key. */
					n = strlen(section);
					if ((strcspn(p, WHITESPACE "/") == n) &&
					    (strncmp(p, section, n) != 0)) {
						continue;
					}
					/* Skip to the section-specific key. */
					p += strcspn(p, WHITESPACE "/");
					p += strspn(p, WHITESPACE "/");
					do {
						/* Compare it to the data, one
						 * word at a time. */
						n = strcspn(p, WHITESPACE);
						if ((strcspn(q, WHITESPACE "=") == n) &&
						    (strncasecmp(p, q, n) == 0)) {
							p += n;
							q += n;
						} else {
							break;
						}
						/* Skip over whitespace. */
						p += strspn(p, WHITESPACE);
						q += strspn(q, WHITESPACE);
					} while ((*p != '\0') && (*q != '\0'));
					/* At this point the query string is
					 * ended and the data string, if it
					 * matched, starts with "=". */
					if ((*p == '\0') && (*q == '=')) {
						/* Skip the "=" and spaces. */
						q++;
						q += strspn(q, WHITESPACE);
						/* Copy the value to the
						 * caller-supplied buffer. */
						memset(scrape_args[i].buf, '\0',
						       scrape_args[i].buflen);
						strncpy(scrape_args[i].buf,
							q,
							scrape_args[i].buflen - 1);
						/* Snip off any newlines. */
						q = scrape_args[i].buf;
						q += strcspn(q, NEWLINES);
						*q = '\0';
					}
				}
			}
			free(section);
			free(line);
			fclose(fp);
		}
		waitpid(pid, NULL, 0);
		break;
	}
	free(scrape_args);
	return;
}

static int
hex2val(int hex)
{
	switch (hex) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return hex - '0';
		break;
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
		return hex - 'A';
		break;
	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
		return hex - 'a';
		break;
	default:
		return 0;
		break;
	}
}

void
scrape_tdb(const char *path, ...)
{
	pid_t pid;
	int i, pipefd[2];
	FILE *fp;
	char *line, *q, *thiskey, *thisdata;
	const char *p;
	size_t n, n_args;
	struct scrape_arg *scrape_args;
	va_list args;

	va_start(args, path);
	n = 0;
	while ((p = va_arg(args, const char*)) != NULL) {
		p = va_arg(args, char*);
		i = va_arg(args, size_t);
		n++;
	}
	va_end(args);

	n_args = n;
	scrape_args = NULL;
	oddjob_resize_array((void **)&scrape_args, sizeof(scrape_args[0]),
			    0, n_args);

	va_start(args, path);
	for (n = 0; n < n_args; n++) {
		scrape_args[n].key = va_arg(args, const char*);
		scrape_args[n].buf = va_arg(args, char*);
		scrape_args[n].buflen = va_arg(args, size_t);
	}
	va_end(args);

	if (pipe(pipefd) == -1) {
		free(scrape_args);
		return;
	}
	pid = fork();
	switch (pid) {
	case -1:
		close(pipefd[0]);
		close(pipefd[1]);
		free(scrape_args);
		return;
	case 0:
		for (i = 0; i < sysconf(_SC_OPEN_MAX); i++) {
			if (i != pipefd[1]) {
				close(i);
			}
		}
		if (pipefd[1] != STDOUT_FILENO) {
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[1]);
		}
		execl(PATH_TDBDUMP, PATH_TDBDUMP, path, NULL);
		_exit(1);
		break;
	default:
		close(pipefd[1]);
		fp = fdopen(pipefd[0], "r");
		if (fp != NULL) {
			line = NULL;
			n = 0;
			thiskey = thisdata = NULL;
			while (getline(&line, &n, fp) != -1) {
				p = line + strspn(line, WHITESPACE);
				if ((strcspn(p, WHITESPACE "=") >= 3) &&
				    (strncmp(p, "key", 3) == 0)) {
					p += 3;
					if (*p == '(') {
						p += strcspn(p, ")");
						if (*p == ')') {
							p++;
						}
					}
					p += strspn(p, WHITESPACE "=\"");
					free(thiskey);
					thiskey = strdup(p);
					q = thiskey + strcspn(thiskey, "\"");
					*q = '\0';
				} else
				if ((strcspn(p, WHITESPACE "=") >= 4) &&
				    (strncmp(p, "data", 4) == 0)) {
					p += 4;
					if (*p == '(') {
						p += strcspn(p, ")");
						if (*p == ')') {
							p++;
						}
					}
					p += strspn(p, WHITESPACE "=\"");
					free(thisdata);
					thisdata = strdup(p);
					q = thisdata + strcspn(thisdata, "\"");
					*q = '\0';
				} else
				if (*p == '{') {
					free(thiskey);
					thiskey = NULL;
					free(thisdata);
					thisdata = NULL;
				} else
				if (*p == '}') {
					for (n = 0;
					     (thiskey != NULL) && (n < n_args);
					     n++) {
						if (strcmp(scrape_args[n].key,
							   thiskey) != 0) {
							continue;
						}
						/* Copy the value to the
						 * caller-supplied buffer. */
						memset(scrape_args[n].buf, '\0',
						       scrape_args[n].buflen);
						strncpy(scrape_args[n].buf,
							thisdata,
							scrape_args[n].buflen - 1);
					}
				}
			}
			free(thiskey);
			free(thisdata);
			free(line);
			fclose(fp);
		}
		waitpid(pid, NULL, 0);
		break;
	}
	for (n = 0; n < n_args; n++) {
		p = q = scrape_args[n].buf;
		while (*p != '\0') {
			switch (*p) {
			case '\\':
				if ((p[1] != '\0') && (p[2] != '\0')) {
					*q = hex2val(p[1]) * 16 + hex2val(p[2]);
					q++;
					p += 3;
				} else {
					p++;
				}
				break;
			default:
				*q++ = *p++;
				break;
			}
		}
	}
	free(scrape_args);
	return;
}
