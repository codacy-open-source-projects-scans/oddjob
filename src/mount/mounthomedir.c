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

#include "../config.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include <dbus/dbus.h>
#include "handlers.h"
#include "selinux.h"
#include "util.h"

#define SEP " \t"
#define MYLOCKDIR LOCKDIR "/" PACKAGE "-mounthomedir"

struct usecountlock {
	struct flock lock;
	char *path;
	int fd;
	int32_t count;
};
static void *
lock_get(const char *path)
{
	struct usecountlock *lock;
	unsigned int i;
	char buf[PATH_MAX + 1];
	struct stat st;
	mode_t mode;

	lock = oddjob_malloc0(sizeof(struct usecountlock));
	lock->path = oddjob_malloc0(strlen(MYLOCKDIR) + 1 + strlen(path) + 1);
	snprintf(lock->path, strlen(MYLOCKDIR) + 1 + strlen(path) + 1,
		 "%s/%s", MYLOCKDIR, path);
	for (i = strlen(MYLOCKDIR) + 1; lock->path[i] != '\0'; i++) {
		if (lock->path[i] == '/') {
			lock->path[i] = '>';
		}
	}
	for (i = 0; (lock->path[i] != '\0') && (i < sizeof(buf) - 1); i++) {
		if ((i > 0) && (lock->path[i] == '/')) {
			memset(buf, '\0', sizeof(buf));
			memcpy(buf, lock->path, i);
			if ((stat(buf, &st) == -1) && (errno == ENOENT)) {
				mode = S_IRWXU | S_IXGRP | S_IXOTH;
				oddjob_set_selinux_file_creation_context(buf,
									 mode |
									 S_IFDIR);
				if ((mkdir(buf, mode) == -1) &&
				    (errno != EEXIST)) {
					syslog(LOG_ERR,
					       "unable to create directory "
					       "\"%s\": %s", buf,
					       strerror(errno));
					oddjob_free(lock->path);
					oddjob_free(lock);
					oddjob_unset_selinux_file_creation_context();
					return NULL;
				}
				oddjob_unset_selinux_file_creation_context();
			}
		}
	}
	lock->fd = open(lock->path,
			O_CREAT | O_EXCL | O_RDWR,
			S_IRUSR | S_IWUSR);
	if ((lock->fd == -1) && (errno == EEXIST)) {
		lock->fd = open(lock->path, O_RDWR);
	}
	if (fcntl(lock->fd, F_SETFD, FD_CLOEXEC) == -1) {
		syslog(LOG_ERR,
		       "error setting close-on-exec flag on lock file \"%s\": "
		       "%s", lock->path, strerror(errno));
		oddjob_free(lock->path);
		oddjob_free(lock);
		return NULL;
	}
	if (lock->fd == -1) {
		syslog(LOG_ERR,
		       "error opening lock file \"%s\": %s", lock->path,
		       strerror(errno));
		oddjob_free(lock->path);
		oddjob_free(lock);
		return NULL;
	}
	memset(&lock->lock, 0, sizeof(lock->lock));
	lock->lock.l_type = F_WRLCK;
	lock->lock.l_whence = SEEK_SET;
	lock->lock.l_start = 0;
	lock->lock.l_len = 0;
	if (fcntl(lock->fd, F_SETLKW, &lock->lock) != 0) {
		syslog(LOG_ERR,
		       "error locking lock file \"%s\": %s", lock->path,
		       strerror(errno));
		close(lock->fd);
		oddjob_free(lock->path);
		oddjob_free(lock);
		return NULL;
	}
	read(lock->fd, &lock->count, sizeof(lock->count));
	return lock;
}
static int
lock_read(void *lck)
{
	struct usecountlock *lock;
	lock = lck;
	return lock->count;
}
static void
lock_manipulate(void *lck, int increment)
{
	struct usecountlock *lock;
	lock = lck;
	if (lseek(lock->fd, 0, SEEK_SET) == 0) {
		lock->count += increment;
		if (write(lock->fd, &lock->count,
			  sizeof(lock->count)) != sizeof(lock->count)) {
			lock->count -= increment;
		}
	}
}
static void
lock_release(void *lck)
{
	struct usecountlock *lock;
	lock = lck;
	close(lock->fd);
	oddjob_free(lock->path);
	oddjob_free(lock);
}

enum action_type {
	action_mount,
	action_umount,
};

static int
fork_exec_wait(const char **argv)
{
	pid_t pid;
	int status;

	pid = fork();
	switch (pid) {
	case -1:
		syslog(LOG_ERR, "fork() error: %m");
		return -1;
	case 0:
		execvp(argv[0], (char **) argv);
		syslog(LOG_ERR, "execvp(\"%s\") error: %m", argv[0]);
		_exit(1);
		return -1;
	default:
		waitpid(pid, &status, 0);
		if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
			return 0;
		}
		return status;
		break;
	}
}

static void
userfstab_mount(const char *user, const char *authtok,
		const char *fstype, const char *source, const char *dest,
		enum action_type action, uid_t uid, gid_t gid)
{
	void *lock;
	const char *argv[8];
	char filename[PATH_MAX + 1], options[LINE_MAX];
	int fd;

	/* obtain the lock file for this mountpoint */
	lock = lock_get(dest);
	if (lock == NULL) {
		syslog(LOG_ERR, "unable to lock refcount file for \"%s\"",
		       dest);
		return;
	}

	/* if the task is an unmount, just do it */
	if (action == action_umount) {
		argv[0] = PATH_UMOUNT;
		argv[1] = dest;
		argv[2] = NULL;
		if (lock_read(lock) == 1) {
			fork_exec_wait(argv);
		}
		if (lock_read(lock) > 0) {
			lock_manipulate(lock, -1);
		}
		lock_release(lock);
		return;
	}

	if ((strcmp(fstype, "nfs") == 0) ||
	    (strcmp(fstype, "nfs4") == 0) ||
	    (strcmp(fstype, "ext2") == 0) ||
	    (strcmp(fstype, "ext3") == 0) ||
	    (strcmp(fstype, "shmfs") == 0) ||
	    (strcmp(fstype, "tmpfs") == 0) ||
	    (strcmp(fstype, "ramfs") == 0) ||
	    (strcmp(fstype, "iso9660") == 0)) {
		argv[0] = PATH_MOUNT;
		argv[1] = "-t";
		argv[2] = fstype;
		argv[3] = source;
		argv[4] = dest;
		argv[5] = NULL;
		if (lock_read(lock) == 0) {
			if (oddjob_selinux_mkdir(dest, S_IRWXU,
						 uid, gid) == 0) {
				fork_exec_wait(argv);
			}
		}
		lock_manipulate(lock, 1);
		lock_release(lock);
		return;
	}
	if ((strcmp(fstype, "vfat") == 0) ||
	    (strcmp(fstype, "fat") == 0)) {
		argv[0] = PATH_MOUNT;
		argv[1] = "-t";
		argv[2] = fstype;
		argv[3] = "-o";
		argv[4] = options;
		argv[5] = source;
		argv[6] = dest;
		argv[7] = NULL;
		snprintf(options, sizeof(options),
			 "uid=%lu,gid=%lu,umask=%03o",
			 (unsigned long) uid, (unsigned long) gid, 077);
		if (lock_read(lock) == 0) {
			if (oddjob_selinux_mkdir(dest, S_IRWXU,
						 uid, gid) == 0) {
				fork_exec_wait(argv);
			}
		}
		lock_manipulate(lock, 1);
		lock_release(lock);
		return;
	}
	if (strcmp(fstype, "cifs") == 0) {
		strcpy(filename, "/tmp/mounthomedirXXXXXX");
		fd = mkstemp(filename);
		if (fd == -1) {
			lock_release(lock);
			return;
		}
		argv[0] = PATH_MOUNT;
		argv[1] = "-t";
		argv[2] = fstype;
		argv[3] = "-o";
		argv[4] = options;
		argv[5] = source;
		argv[6] = dest;
		argv[7] = NULL;
		snprintf(options, sizeof(options),
			 "credentials=%s,uid=%lu,gid=%lu",
			 filename, (unsigned long) uid, (unsigned long) gid);
		write(fd, "username=", strlen("username="));
		write(fd, user, strlen(user));
		write(fd, "\npassword=", strlen("\npassword="));
		write(fd, authtok, strlen(authtok));
		write(fd, "\n", strlen("\n"));
		close(fd);
		if (lock_read(lock) == 0) {
			if (oddjob_selinux_mkdir(dest, S_IRWXU,
						 uid, gid) == 0) {
				fork_exec_wait(argv);
			}
		}
		lock_manipulate(lock, 1);
		unlink(filename);
		lock_release(lock);
		return;
	}
}

static void
userfstab(const char *filename, const char *user, const char *authtok,
	  enum action_type action, const char *homedir, uid_t uid, gid_t gid)
{
	FILE *fp;
	int i;
	const char *p, *q;
	char *fstype, *source, path[PATH_MAX + 1], *matchuser, **entries;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		return;
	}
	if (fcntl(fileno(fp), F_SETFD, FD_CLOEXEC) == -1) {
		fclose(fp);
		return;
	}

	entries = oddjob_collect_args(fp);

	for (i = 0; (entries != NULL) && (entries[i] != NULL); i++) {
		/* isolate the first token (user name) */
		p = entries[i] + strspn(entries[i], SEP);
		q = p + strcspn(p, SEP);

		/* is it a comment? */
		if (strchr("#;", *p) != NULL) {
			continue;
		}

		/* does it match the user name? */
		matchuser = oddjob_strndup(p, q - p);
		if (fnmatch(matchuser, user, FNM_NOESCAPE) != 0) {
			oddjob_free(matchuser);
			continue;
		}
		oddjob_free(matchuser);

		/* isolate the filesystem type */
		p = q + strspn(q, SEP);
		q = p + strcspn(p, SEP);
		fstype = oddjob_strndup(p, q - p);

		/* isolate the filesystem source */
		p = q + strspn(q, SEP);
		q = p + strcspn(p, SEP);
		source = oddjob_strndup(p, q - p);

		/* build a path relative to the user's home directory */
		p = q + strspn(q, SEP);
		if (path + snprintf(path, sizeof(path),
				    "%s/%s", homedir, p) >=
		    path + sizeof(path)) {
			syslog(LOG_ERR, "derived path %s/%s would be too long",
			       homedir, p);
			oddjob_free(source);
			oddjob_free(fstype);
			continue;
		}

		/* actually do the mount/umount */
		userfstab_mount(user, authtok, fstype, source, path,
				action, uid, gid);

		oddjob_free(source);
		oddjob_free(fstype);
	}

	oddjob_free_args(entries);
	fclose(fp);
}

int
main(int argc, char **argv)
{
	char **args;
	struct passwd *pwd;
	enum action_type action;
	int i;

	while ((i = getopt(argc, argv, "")) != -1) {
		switch (i) {
		default:
			fprintf(stderr, "No recognized options.\n");
			return 1;
		}
	}

	openlog(PACKAGE "-mounthomedir", LOG_PID, LOG_DAEMON);
	args = oddjob_collect_args(stdin);
	for (i = 0; (args != NULL) && (args[i] != NULL); i++) {
		continue;
	}
	if (i != 3) {
		syslog(LOG_ERR, "invoked with %d arguments, expected 3", i);
		return HANDLER_INVALID_INVOCATION;
	}
	if ((strcmp(args[2], "mount") != 0) &&
	    (strcmp(args[2], "umount") != 0)) {
		syslog(LOG_ERR,
		       "third argument was neither \"mount\" nor \"umount\"");
		return HANDLER_INVALID_INVOCATION;
	}
	if (strcmp(args[2], "mount") == 0) {
		action = action_mount;
	} else {
		if (strcmp(args[2], "umount") == 0) {
			action = action_umount;
		}
	}
	pwd = getpwnam(args[0]);
	if (pwd == NULL) {
		syslog(LOG_ERR, "no such user as \"%s\"", args[0]);
		return HANDLER_INVALID_INVOCATION;
	}
	userfstab(SYSCONFDIR "/" PACKAGE "/userfstab",
		  args[0], args[1], action,
		  pwd->pw_dir, pwd->pw_uid, pwd->pw_gid);
	oddjob_free_args(args);
	closelog();
	return 0;
}
