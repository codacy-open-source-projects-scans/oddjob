/*
   Copyright 2005,2006,2007,2011 Red Hat, Inc.
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
#include <ftw.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <dbus/dbus.h>
#include "handlers.h"
#include "selinux.h"
#include "util.h"

#define _(_x) _x

static const char *skel;
static const char *skel_dir;
static struct passwd *pwd;
static mode_t override_umask;
static int owner_mkdir_first = 0;

#define FLAG_POPULATE	(1 << 0)
#define FLAG_QUIET	(1 << 1)
#define FLAG_OWNER_MKDIR_FIRST (1 << 2)

/* Given the path of an item somewhere in the skeleton directory, create as
 * identical as possible a copy in the destination tree. */
static int
copy_single_item(const char *source, const struct stat *sb,
		 int flag, struct FTW *status)
{
	uid_t uid = pwd->pw_uid;
	gid_t gid = pwd->pw_gid;
	mode_t mode = sb->st_mode & ~override_umask;
	int sfd, dfd, i, res;
	char target[PATH_MAX + 1], newpath[PATH_MAX + 1];
	unsigned char buf[BUFSIZ];
	/* Generate the name of the new item. */
	if (snprintf(newpath, sizeof(newpath), "%s%s",
		     pwd->pw_dir,
		     source + strlen(skel)) > (int) sizeof(newpath)) {
		/* The path would be too long(!), so give up. */
		syslog(LOG_ERR, "pathname (%s%s) would be too long",
		       pwd->pw_dir, source + strlen(skel));
		return HANDLER_INVALID_INVOCATION;
	}
	switch (flag) {
	case FTW_SL:
		/* It's a symlink.  Read its target and create a copy. */
		memset(&target, '\0', sizeof(target));
		if (readlink(source, target, sizeof(target) - 1)) {
			oddjob_set_selinux_file_creation_context(newpath,
								 sb->st_mode |
								 S_IFLNK);
			if (symlink(target, newpath) == 0) {
				if (lchown(newpath, pwd->pw_uid, pwd->pw_gid) == -1) {
					syslog(LOG_ERR,
					       "error setting owner of \"%s\": "
					       "%m", newpath);
					unlink(newpath);
					return HANDLER_FAILURE;
				}
			} else {
				oddjob_unset_selinux_file_creation_context();
				syslog(LOG_ERR, "error creating %s: %m",
				       target);
				return HANDLER_FAILURE;
			}
			oddjob_unset_selinux_file_creation_context();
			return 0;
		}
		break;
	case FTW_F:
		/* It's a file.  Make a copy. */
		sfd = open(source, O_RDONLY);
		if (sfd != -1) {
			oddjob_set_selinux_file_creation_context(newpath,
								 sb->st_mode |
								 S_IFREG);
			dfd = open(newpath, O_WRONLY | O_CREAT | O_EXCL, mode);
			if (dfd != -1) {
				while ((i = read(sfd, buf, sizeof(buf))) > 0) {
					retry_write(dfd, buf, i);
				}
				if (fchown(dfd, pwd->pw_uid, pwd->pw_gid) == -1) {
					syslog(LOG_ERR,
					       "error setting owner of \"%s\": "
					       "%m", newpath);
					unlink(newpath);
					close(sfd);
					close(dfd);
					return HANDLER_FAILURE;
				} else {
					if (fchmod(dfd,
						   sb->st_mode &
						   ~override_umask) == -1) {
						syslog(LOG_ERR,
						       "error setting mode of "
						       "\"%s\": %m", newpath);
						unlink(newpath);
						close(sfd);
						close(dfd);
						return HANDLER_FAILURE;
					}
				}
				close(dfd);
			} else {
				if (errno != EEXIST) {
					syslog(LOG_ERR, "error creating %s: %m",
					       newpath);
					close(sfd);
					return HANDLER_FAILURE;
				}
			}
			close(sfd);
			oddjob_unset_selinux_file_creation_context();
		} else {
			syslog(LOG_ERR, "error opening %s: %m", source);
			return HANDLER_FAILURE;
		}
		return 0;
	case FTW_D:
		/* It's a directory.  Make one with the same name and
		 * permissions, but owned by the target user. */
		if (status->level == 0) {
			/* It's the home directory itself.  Use the configured
			 * (or overriden) mode, not the source mode & umask. */
			mode = 0777 & ~override_umask;

			/* Don't give it to the target user just yet to avoid
			 * potential race conditions involving symlink attacks
			 * when we copy over the skeleton tree. */
			if (!owner_mkdir_first) {
				uid = 0;
				gid = 0;
			}
		}
		res = oddjob_selinux_mkdir(newpath, mode, uid, gid);

		/* on unexpected errors, or if the home directory itself
		 * suddenly already exists, abort the copy operation. */
		if (res != 0 && (errno != EEXIST || status->level == 0)) {
			return HANDLER_FAILURE;
		}
		return 0;
	case FTW_NS:
	default:
		return 0;
	}
	return 0;
}

/*
 * get_skel_dir
 *
 * Returns: the location on the filesystem where the contents of a new user's
 * home directory should be found.  FIXME: consult /etc/default/useradd.
 *
 */
static const char *
get_skel_dir(void)
{
	return skel_dir ? skel_dir : "/etc/skel";
}

/* Create a copy of /etc/skel in the named user's home directory. */
static int
mkhomedir(const char *user, int flags)
{
	struct stat st;

	/* Now make sure that the user
	   a) exists
	   b) has a home directory specified which is
	      1) an absolute pathname
	      2) not an empty string
	      3) not already there */
	pwd = getpwnam(user);
	if (pwd == NULL) {
		syslog(LOG_ERR, "could not look up location of home directory "
		       "for %s", user);
		return HANDLER_INVALID_INVOCATION;
	}
	if (pwd->pw_dir == NULL) {
		syslog(LOG_ERR, "user %s has NULL home directory", user);
		return HANDLER_INVALID_INVOCATION;
	}
	if ((strlen(pwd->pw_dir) == 0) || (pwd->pw_dir[0] != '/')) {
		syslog(LOG_ERR, "user %s has weird home directory (%s)", user,
		       pwd->pw_dir);
		return HANDLER_INVALID_INVOCATION;
	}
	if (flags & FLAG_OWNER_MKDIR_FIRST) {
		owner_mkdir_first = 1;
	}
	if ((lstat(pwd->pw_dir, &st) == -1) && (errno == ENOENT)) {
		/* Figure out which location we're using as a
		 * template. */
		skel = get_skel_dir();
		if (skel != NULL) {
			/* Set the text of the result message. */
			if (!(flags & FLAG_QUIET)) {
				printf(_("Creating home directory for %s."),
				       user);
			}
			/* Walk the template tree and make a copy. */
			if (flags & FLAG_POPULATE) {
				int res = nftw(get_skel_dir(), copy_single_item, 5,
					       FTW_PHYS);
				/* only now give ownership to the target user */
				if (res == 0 && !owner_mkdir_first) {
					res = chown(pwd->pw_dir, pwd->pw_uid, pwd->pw_gid);
				}

				return res;
			} else {
				if ((oddjob_selinux_mkdir(pwd->pw_dir,
							  0777 & ~override_umask,
							  pwd->pw_uid,
							  pwd->pw_gid) != 0) &&
				    (errno != EEXIST)) {
					syslog(LOG_ERR,
					       "error creating \"%s\": %m",
					       pwd->pw_dir);
					return HANDLER_FAILURE;
				}
			}
		}
	}
	return 0;
}

static mode_t
get_umask(int *configured, const char *variable, mode_t default_value)
{
	FILE *fp;
	char buf[BUFSIZ], *p, *end;
	mode_t mask = default_value;
	long tmp;
	size_t vlen = strlen(variable);

	fp = fopen("/etc/login.defs", "r");
	if (fp != NULL) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			if (buf[0] == '#') {
				continue;
			}
			buf[strcspn(buf, "\r\n")] = '\0';
			p = buf + strspn(buf, " \t");
			if (strncmp(p, variable, vlen) != 0) {
				continue;
			}
			p += vlen;
			if (strspn(p, " \t") == 0) {
				continue;
			}
			p += strspn(p, " \t");
			tmp = strtol(p, &end, 0);
			if ((end != NULL) && (*end == '\0')) {
				mask = tmp;
				if (configured) {
					*configured = 1;
				}
				break;
			}
		}
		fclose(fp);
	}
	return mask;
}

int
main(int argc, char **argv)
{
	char **args, *p;
	int i, configured_umask = 0, flags = FLAG_POPULATE;

	openlog(PACKAGE "-mkhomedir", LOG_PID, LOG_DAEMON);
	/* Unlike UMASK, HOME_MODE is the file mode, so needs to be reverted */
	override_umask = 0777 & ~get_umask(&configured_umask, "HOME_MODE", 0);
	if (configured_umask == 0) {
		override_umask = get_umask(&configured_umask, "UMASK", 022);
	}
	skel_dir = "/etc/skel";

	while ((i = getopt(argc, argv, "nqfs:u:")) != -1) {
		switch (i) {
		case 'f':
			flags |= FLAG_OWNER_MKDIR_FIRST;
			break;
		case 'n':
			flags &= ~FLAG_POPULATE;
			break;
		case 'q':
			flags |= FLAG_QUIET;
			break;
		case 's':
			skel_dir = optarg;
			break;
		case 'u':
			override_umask = strtol(optarg, &p, 0);
			if ((p == NULL) || (*p != '\0')) {
				fprintf(stderr, "Invalid umask \"%s\".\n",
					optarg);
				return 1;
			}
			configured_umask = 0;
			break;
		default:
			fprintf(stderr, "Valid options:\n"
				"-f\tCreate home directory initially owned by user, "
				"not root. See man page for security issues.\n"
				"-n\tDo not populate home directories, "
				"just create them.\n"
				"-q\tDo not print messages when creating "
				"a directory.\n"
				"-s PATH\tOverride the skeleton directory "
				"path (\"%s\").\n"
				"-u MASK\tOverride the default umask (0%03o%s).\n",
				skel_dir, override_umask,
				configured_umask ?
				", from /etc/login.defs" :
				"");
			return 1;
		}
	}
	args = oddjob_collect_args(stdin);
	umask(override_umask);
	for (i = 0; (args != NULL) && (args[i] != NULL); i++) {
		if (strlen(args[i]) > 0) {
			i = mkhomedir(args[i], flags);
			oddjob_free_args(args);
			closelog();
			return i;
		}
	}
	oddjob_free_args(args);
	syslog(LOG_ERR, "invoked with no non-empty arguments");
	closelog();
	return HANDLER_INVALID_INVOCATION;
}
