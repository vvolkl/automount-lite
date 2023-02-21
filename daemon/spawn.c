/* ----------------------------------------------------------------------- *
 * 
 *  spawn.c - run programs synchronously with output redirected to syslog
 *   
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2005 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <grp.h>
#include <time.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <pwd.h>

#include "automount.h"

static pthread_mutex_t spawn_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t open_mutex = PTHREAD_MUTEX_INITIALIZER;

#define SPAWN_OPT_NONE		0x0000
#define SPAWN_OPT_LOCK		0x0001
#define SPAWN_OPT_OPEN		0x0002

#define MTAB_LOCK_RETRIES	3

void dump_core(void)
{
	sigset_t segv;

	sigemptyset(&segv);
	sigaddset(&segv, SIGSEGV);
	pthread_sigmask(SIG_UNBLOCK, &segv, NULL);

	raise(SIGSEGV);
}

void open_mutex_lock(void)
{
	int _o_lock = pthread_mutex_lock(&open_mutex);
	if (_o_lock)
		fatal(_o_lock);
}

void open_mutex_unlock(void)
{
	int _o_unlock = pthread_mutex_unlock(&open_mutex);
	if (_o_unlock)
		fatal(_o_unlock);
}

/*
 * Use CLOEXEC flag for open(), pipe(), fopen() (read-only case) and
 * socket() if possible.
 */
static int cloexec_works = 0;

static void check_cloexec(int fd)
{
	if (cloexec_works == 0) {
		int fl = fcntl(fd, F_GETFD);
		if (fl != -1)
			cloexec_works = (fl & FD_CLOEXEC) ? 1 : -1;
	}
	if (cloexec_works > 0)
		return;
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	return;
}

int open_fd(const char *path, int flags)
{
	int fd;

	open_mutex_lock();
#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC)
	if (cloexec_works != -1)
		flags |= O_CLOEXEC;
#endif
	fd = open(path, flags);
	if (fd == -1) {
		char buf[MAX_ERR_BUF];
		char *estr;

		open_mutex_unlock();
		estr = strerror_r(errno, buf, sizeof(buf));
		logerr("failed to open file: %s", estr);
		return -1;
	}
	check_cloexec(fd);
	open_mutex_unlock();
	return fd;
}

int open_fd_mode(const char *path, int flags, int mode)
{
	int fd;

	open_mutex_lock();
#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC)
	if (cloexec_works != -1)
		flags |= O_CLOEXEC;
#endif
	fd = open(path, flags, mode);
	if (fd == -1) {
		char buf[MAX_ERR_BUF];
		char *estr;

		open_mutex_unlock();
		estr = strerror_r(errno, buf, sizeof(buf));
		logerr("failed to open file: %s", estr);
		return -1;
	}
	check_cloexec(fd);
	open_mutex_unlock();
	return fd;
}

int open_pipe(int pipefd[2])
{
	char buf[MAX_ERR_BUF];
	char *estr;
	int ret;

	open_mutex_lock();
#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC) && defined(HAVE_PIPE2)
	if (cloexec_works != -1) {
		ret = pipe2(pipefd, O_CLOEXEC);
		if (ret != -1)
			goto done;
		if (errno != EINVAL)
			goto err;
	}
#endif
	ret = pipe(pipefd);
	if (ret == -1)
		goto err;
	check_cloexec(pipefd[0]);
	check_cloexec(pipefd[1]);
done:
	open_mutex_unlock();
	return 0;
err:
	open_mutex_unlock();
	estr = strerror_r(errno, buf, sizeof(buf));
	logerr("failed to open pipe: %s", estr);
	return -1;
}

int open_sock(int domain, int type, int protocol)
{
	int fd;

	open_mutex_lock();
#ifdef SOCK_CLOEXEC
	if (cloexec_works != -1)
		type |= SOCK_CLOEXEC;
#endif
	fd = socket(domain, type, protocol);
	if (fd == -1) {
		char buf[MAX_ERR_BUF];
		char *estr;

		open_mutex_unlock();
		estr = strerror_r(errno, buf, sizeof(buf));
		logerr("failed to open socket: %s", estr);
		return -1;
	}
	check_cloexec(fd);
	open_mutex_unlock();
	return fd;
}

FILE *open_fopen_r(const char *path)
{
	FILE *f;

	open_mutex_lock();
#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC)
	if (cloexec_works != -1) {
		f = fopen(path, "re");
		if (f != NULL) {
			check_cloexec(fileno(f));
			open_mutex_unlock();
			return f;
		}
	}
#endif
	f = fopen(path, "r");
	if (f == NULL) {
		char buf[MAX_ERR_BUF];
		char *estr;

		open_mutex_unlock();
		estr = strerror_r(errno, buf, sizeof(buf));
		logerr("failed to open file: %s", estr);
		return NULL;
	}
	check_cloexec(fileno(f));
	open_mutex_unlock();
	return f;
}

FILE *open_setmntent_r(const char *table)
{
	FILE *tab;

	open_mutex_lock();
#if defined(O_CLOEXEC) && defined(SOCK_CLOEXEC)
	if (cloexec_works != -1) {
		tab = setmntent(table, "re");
		if (tab != NULL) {
			check_cloexec(fileno(tab));
			open_mutex_unlock();
			return tab;
		}
	}
#endif
	tab = fopen(table, "r");
	if (tab == NULL) {
		char buf[MAX_ERR_BUF];
		char *estr;

		open_mutex_unlock();
		estr = strerror_r(errno, buf, sizeof(buf));
		logerr("failed to open mount table: %s", estr);
		return NULL;
	}
	check_cloexec(fileno(tab));
	open_mutex_unlock();
	return tab;
}

/*
 * Used by subprocesses which exec to avoid carrying over the main
 * daemon's signalling environment
 */
void reset_signals(void)
{
	struct sigaction sa;
	sigset_t allsignals;
	int i;

	sigfillset(&allsignals);
	sigprocmask(SIG_BLOCK, &allsignals, NULL);

	/* Discard all pending signals */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	for (i = 1; i < NSIG; i++)
		if (i != SIGKILL && i != SIGSTOP)
			sigaction(i, &sa, NULL);

	sa.sa_handler = SIG_DFL;

	for (i = 1; i < NSIG; i++)
		if (i != SIGKILL && i != SIGSTOP)
			sigaction(i, &sa, NULL);

	/* Ignore the user signals that may be sent so that we
	 *  don't terminate execed program by mistake */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	sigprocmask(SIG_UNBLOCK, &allsignals, NULL);
}

#define ERRBUFSIZ 2047		/* Max length of error string excl \0 */

static int timed_read(int pipe, char *buf, size_t len, int time)
{
	struct pollfd pfd[1];
	int timeout = time;
	int ret;

	pfd[0].fd = pipe;
	pfd[0].events = POLLIN;

	if (time != -1) {
		if (time >= (INT_MAX - 1)/1000)
			timeout = INT_MAX - 1;
		else
			timeout = time * 1000;
	}

	ret = poll(pfd, 1, timeout);
	if (ret <= 0) {
		if (ret == 0)
			ret = -ETIMEDOUT;
		return ret;
	}

	if (pfd[0].fd == -1)
		return 0;

	if ((pfd[0].revents & (POLLIN|POLLHUP)) == POLLHUP)
		return 0;

	while ((ret = read(pipe, buf, len)) == -1 && errno == EINTR);

	return ret;
}

static int do_spawn(unsigned logopt, unsigned int wait,
		    unsigned int options, const char *prog,
		    const char *const *argv)
{
	pid_t f;
	int ret, status, pipefd[2];
	char errbuf[ERRBUFSIZ + 1], *p, *sp;
	int errp, errn;
	int cancel_state;
	unsigned int use_lock = options & SPAWN_OPT_LOCK;
	unsigned int use_open = options & SPAWN_OPT_OPEN;
	sigset_t allsigs, tmpsig, oldsig;
	struct thread_stdenv_vars *tsv;
	pid_t euid = 0;
	gid_t egid = 0;
	gid_t *groups = NULL;
	gid_t *saved_groups = NULL;
	int ngroups = 0;
	int nsaved_groups = 0;

	if (open_pipe(pipefd))
		return -1;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	sigfillset(&allsigs);
	pthread_sigmask(SIG_BLOCK, &allsigs, &oldsig);

	if (use_lock) {
		status = pthread_mutex_lock(&spawn_mutex);
		if (status)
			fatal(status);
	}

	tsv = pthread_getspecific(key_thread_stdenv_vars);
	if (tsv) {
		euid = tsv->uid;
		egid = tsv->gid;
	}

	open_mutex_lock();

	if (euid) {
		struct passwd *pwd;

		pwd = getpwuid(getuid());
		if (!pwd)
			fprintf(stderr,
				"warning: getpwuid: can't get current username\n");
		else {
			/* get number of groups for current gid */
			getgrouplist(pwd->pw_name, getgid(), NULL, &nsaved_groups);
			saved_groups = malloc(nsaved_groups * sizeof(gid_t));

			/* get current gid groups list */
			getgrouplist(pwd->pw_name, getgid(), saved_groups, &nsaved_groups);
		}

		/* get number of groups of mount triggering process */
		getgrouplist(tsv->user, egid, NULL, &ngroups);
		groups = malloc(ngroups * sizeof(gid_t));

		/* get groups list of mount triggering process */
		getgrouplist(tsv->user, egid, groups, &ngroups);
	}

	f = fork();
	if (f == 0) {
		char **pargv = (char **) argv;
		int loc = 0;

		reset_signals();
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		open_mutex_unlock();

		/* what to mount must always be second last */
		while (*pargv++)
			loc++;
		if (loc <= 3)
			goto done;
		loc -= 2;

		/*
		 * If the mount location starts with a "/" then it is
		 * a local path. In this case it is a bind mount, a
		 * loopback mount or a file system that uses a local
		 * path so we need to check for dependent mounts.
		 *
		 * I hope host names are never allowed "/" as first char
		 */
		if (use_open && *(argv[loc]) == '/') {
			char **p;
			int is_bind, fd;

			pid_t pgrp = getpgrp();

			/*
			 * Pretend to be requesting user and set non-autofs
			 * program group to trigger mount
			 */
			if (euid) {
				if (!tsv->user)
					fprintf(stderr,
						"warning: can't init groups\n");
				else if (groups) {
					if (setgroups(ngroups, groups) == -1)
						fprintf(stderr,
							"warning: setgroups: %s\n",
							strerror(errno));
					free(groups);
				}

				if (setegid(egid) == -1)
					fprintf(stderr,
						"warning: setegid: %s\n",
						strerror(errno));
				if (seteuid(euid) == -1)
					fprintf(stderr,
						"warning: seteuid: %s\n",
						strerror(errno));
			}
			setpgrp();

			/*
			 * Trigger the recursive mount.
			 *
			 * Ignore the open(2) return code as there may be
			 * multiple waiters for this mount and we need to
			 * let the VFS handle returns to each individual
			 * waiter.
			 */
			fd = open(argv[loc], O_DIRECTORY);
			if (fd != -1)
				close(fd);

			if (seteuid(0) == -1)
				fprintf(stderr,
					"warning: seteuid: %s\n",
					strerror(errno));
			if (setegid(0) == -1)
				fprintf(stderr,
					"warning: setegid: %s\n",
					strerror(errno));
			if (pgrp >= 0)
				setpgid(0, pgrp);
			/* Reset groups for trigger of trailing mount */
			if (euid && saved_groups) {
				setgroups(nsaved_groups, saved_groups);
				free(saved_groups);
			}

			/*
			 * The kernel leaves mount type autofs alone because
			 * they are supposed to be autofs sub-mounts and they
			 * look after their own expiration. So mounts bound
			 * to an autofs submount won't ever be expired.
			 */
			is_bind = 0;
			p = (char **) argv;
			while (*p) {
				if (strcmp(*p, "--bind")) {
					p++;
					continue;
				}
				is_bind = 1;
				break;
			}
			if (!is_bind)
				goto done;

			if (is_mounted(argv[loc], MNTS_AUTOFS)) {
				fprintf(stderr,
				     "error: can't bind to an autofs mount\n");
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
				 _exit(EINVAL);
			}
		}
done:
		execv(prog, (char *const *) argv);
		_exit(255);	/* execv() failed */
	} else {
		tmpsig = oldsig;

		sigaddset(&tmpsig, SIGCHLD);
		pthread_sigmask(SIG_SETMASK, &tmpsig, NULL);
		open_mutex_unlock();

		if (groups)
			free(groups);
		if (saved_groups)
			free(saved_groups);

		close(pipefd[1]);

		if (f < 0) {
			close(pipefd[0]);
			if (use_lock) {
				status = pthread_mutex_unlock(&spawn_mutex);
				if (status)
					fatal(status);
			}
			pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
			pthread_setcancelstate(cancel_state, NULL);
			return -1;
		}

		errp = 0;
		do {
			errn = timed_read(pipefd[0],
					  errbuf + errp, ERRBUFSIZ - errp, wait);
			if (errn > 0) {
				errp += errn;

				sp = errbuf;
				while (errp && (p = memchr(sp, '\n', errp))) {
					*p++ = '\0';
					if (sp[0])	/* Don't output empty lines */
						debug(logopt, ">> %s", sp);
					errp -= (p - sp);
					sp = p;
				}

				if (errp && sp != errbuf)
					memmove(errbuf, sp, errp);

				if (errp >= ERRBUFSIZ) {
					/* Line too long, split */
					errbuf[errp] = '\0';
					debug(logopt, ">> %s", errbuf);
					errp = 0;
				}
			}
		} while (errn > 0);

		if (errn == -ETIMEDOUT)
			kill(f, SIGTERM);

		close(pipefd[0]);

		if (errp > 0) {
			/* End of file without \n */
			errbuf[errp] = '\0';
			debug(logopt, ">> %s", errbuf);
		}

		if (waitpid(f, &ret, 0) != f)
			ret = -1;	/* waitpid() failed */

		if (use_lock) {
			status = pthread_mutex_unlock(&spawn_mutex);
			if (status)
				fatal(status);
		}
		pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
		pthread_setcancelstate(cancel_state, NULL);

		return ret;
	}
}

int spawnv(unsigned logopt, const char *prog, const char *const *argv)
{
	return do_spawn(logopt, -1, SPAWN_OPT_NONE, prog, argv);
}

int spawnl(unsigned logopt, const char *prog, ...)
{
	va_list arg;
	int argc, ret;
	char **argv, **p;
	unsigned int argv_len;

	va_start(arg, prog);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	argv_len = sizeof(char *) * (argc + 1);
	argv = malloc(argv_len);
	if (!argv) {
		char buf[MAX_ERR_BUF];
		char *estr = strerror_r(errno, buf, sizeof(buf));
		crit(logopt, "malloc: %s", estr);
		return -1;
	}
	memset(argv, 0, argv_len);

	va_start(arg, prog);
	p = argv;
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	ret = do_spawn(logopt, -1, SPAWN_OPT_NONE, prog, (const char **) argv);
	free(argv);

	return ret;
}

int spawn_mount(unsigned logopt, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;
	char prog[] = PATH_MOUNT;
	char arg0[] = PATH_MOUNT;
	char argn[] = "-n";
	char argvr[] = "-v";
	/* In case we need to use the fake option to mount */
	char arg_fake[] = "-f";
	unsigned int options;
	unsigned int retries = MTAB_LOCK_RETRIES;
	int update_mtab = 1, ret, printed = 0;
	unsigned int wait = defaults_get_mount_wait();
	int verbose = defaults_get_mount_verbose();
	char buf[PATH_MAX + 1];
	unsigned int argv_len;

	/* If we use mount locking we can't validate the location */
#ifdef ENABLE_MOUNT_LOCKING
	options = SPAWN_OPT_LOCK;
#else
	options = SPAWN_OPT_OPEN;
#endif

	va_start(arg, logopt);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	ret = readlink(_PATH_MOUNTED, buf, PATH_MAX);
	if (ret != -1) {
		buf[ret] = '\0';
		if (!strcmp(buf, _PROC_MOUNTS) ||
		    !strcmp(buf, _PROC_SELF_MOUNTS)) {
			debug(logopt,
			      "mtab link detected, passing -n to mount");
			argc++;
			update_mtab = 0;
		}
	}

	/* Alloc 2 extra slots in case we need to use the "-f" or "-v" options
	 * plus the NULL slot for end of args.
	 */
	argv_len = sizeof(char *) * (argc + 3);
	argv = malloc(argv_len);
	if (!argv) {
		char buf[MAX_ERR_BUF];
		char *estr = strerror_r(errno, buf, sizeof(buf));
		crit(logopt, "malloc: %s", estr);
		return -1;
	}
	memset(argv, 0, argv_len);

	argv[0] = arg0;

	va_start(arg, logopt);
	p = argv + 1;
	if (!update_mtab)
		*(p++) = argn;
	if (verbose)
		*(p++) = argvr;

	while ((*p = va_arg(arg, char *))) {
		if (options == SPAWN_OPT_OPEN && !strcmp(*p, "-t")) {
			*(++p) = va_arg(arg, char *);
			if (!*p)
				break;
			/*
			 * A cifs mount location begins with a "/" but
			 * is not a local path, so don't try to resolve
			 * it. Mmmm ... does anyone use smbfs these days?
			 */
			if (strstr(*p, "cifs"))
				options = SPAWN_OPT_NONE;
		}
		p++;
	}
	va_end(arg);

	while (retries--) {
		ret = do_spawn(logopt, wait, options, prog, (const char **) argv);
		if (ret == MTAB_NOTUPDATED) {
			struct timespec tm = {3, 0};

			/*
			 * If the mount succeeded but the mtab was not
			 * updated, then retry the mount with the -f (fake)
			 * option to just update the mtab.
			 */
			if (!printed) {
				debug(logopt, "mount failed with error code 16"
				      ", retrying with the -f option");
				printed = 1;
			}

			/*
			 * Move the last two args so do_spawn() can find the
			 * mount target.
			 */
			if (!argv[argc]) {
				argv[argc + 1] = NULL;
				argv[argc] = argv[argc - 1];
				argv[argc - 1] = argv[argc - 2];
				argv[argc - 2] = arg_fake;
			}

			nanosleep(&tm, NULL);

			continue;
		}
		break;
	}

	/* This is not a fatal error */
	if (ret == MTAB_NOTUPDATED) {
		/*
		 * Version 5 requires that /etc/mtab be in sync with
		 * /proc/mounts. If we're unable to update matb after
		 * retrying then we have no choice but umount the mount
		 * and return a fail.
		 */
		warn(logopt,
		     "Unable to update the mtab file, forcing mount fail!");
		umount(argv[argc]);
		ret = MNT_FORCE_FAIL;
	}
	free(argv);

	return ret;
}

/*
 * For bind mounts that depend on the target being mounted (possibly
 * itself an automount) we attempt to mount the target using an open(2)
 * call. For this to work the location must be the second last arg.
 *
 * NOTE: If mount locking is enabled this type of recursive mount cannot
 *	 work.
 */
int spawn_bind_mount(unsigned logopt, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;
	char prog[] = PATH_MOUNT;
	char arg0[] = PATH_MOUNT;
	char bind[] = "--bind";
	char argn[] = "-n";
	/* In case we need to use the fake option to mount */
	char arg_fake[] = "-f";
	unsigned int options;
	unsigned int retries = MTAB_LOCK_RETRIES;
	int update_mtab = 1, ret, printed = 0;
	unsigned int wait = defaults_get_mount_wait();
	char buf[PATH_MAX + 1];
	unsigned int argv_len;

	/* If we use mount locking we can't validate the location */
#ifdef ENABLE_MOUNT_LOCKING
	options = SPAWN_OPT_LOCK;
#else
	options = SPAWN_OPT_OPEN;
#endif

	/*
	 * Alloc 2 extra slots, one for the bind option and one in case
	 * we need to use the "-f" option
	 */
	va_start(arg, logopt);
	for (argc = 2; va_arg(arg, char *); argc++);
	va_end(arg);

	ret = readlink(_PATH_MOUNTED, buf, PATH_MAX);
	if (ret != -1) {
		buf[ret] = '\0';
		if (!strcmp(buf, _PROC_MOUNTS) ||
		    !strcmp(buf, _PROC_SELF_MOUNTS)) {
			debug(logopt,
			      "mtab link detected, passing -n to mount");
			argc++;
			update_mtab = 0;
		}
	}

	argv_len = sizeof(char *) * (argc + 2);
	argv = malloc(argv_len);
	if (!argv) {
		char buf[MAX_ERR_BUF];
		char *estr = strerror_r(errno, buf, sizeof(buf));
		crit(logopt, "malloc: %s", estr);
		return -1;
	}
	memset(argv, 0, argv_len);

	argv[0] = arg0;
	argv[1] = bind;

	va_start(arg, logopt);
	if (update_mtab)
		p = argv + 2;
	else {
		argv[2] = argn;
		p = argv + 3;
	}
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	while (retries--) {
		ret = do_spawn(logopt, wait, options, prog, (const char **) argv);
		if (ret == MTAB_NOTUPDATED) {
			struct timespec tm = {3, 0};

			/*
			 * If the mount succeeded but the mtab was not
			 * updated, then retry the mount with the -f (fake)
			 * option to just update the mtab.
			 */
			if (!printed) {
				debug(logopt, "mount failed with error code 16"
				      ", retrying with the -f option");
				printed = 1;
			}

			/*
			 * Move the last two args so do_spawn() can find the
			 * mount target.
			 */
			if (!argv[argc]) {
				argv[argc + 1] = NULL;
				argv[argc] = argv[argc - 1];
				argv[argc - 1] = argv[argc - 2];
				argv[argc - 2] = arg_fake;
			}

			nanosleep(&tm, NULL);

			continue;
		}
		break;
	}

	/* This is not a fatal error */
	if (ret == MTAB_NOTUPDATED) {
		/*
		 * Version 5 requires that /etc/mtab be in sync with
		 * /proc/mounts. If we're unable to update matb after
		 * retrying then we have no choice but umount the mount
		 * and return a fail.
		 */
		warn(logopt,
		     "Unable to update the mtab file, forcing mount fail!");
		umount(argv[argc]);
		ret = MNT_FORCE_FAIL;
	}
	free(argv);

	return ret;
}

int spawn_umount(unsigned logopt, ...)
{
	va_list arg;
	int argc;
	char **argv, **p;
	char prog[] = PATH_UMOUNT;
	char arg0[] = PATH_UMOUNT;
#ifdef HAVE_NO_CANON_UMOUNT
	char * const arg_c = "-c";
#else
	char * const arg_c = NULL;
#endif
	char argn[] = "-n";
	unsigned int options;
	unsigned int retries = MTAB_LOCK_RETRIES;
	int update_mtab = 1, ret, printed = 0;
	unsigned int wait = defaults_get_umount_wait();
	char buf[PATH_MAX + 1];
	unsigned int argv_len;

#ifdef ENABLE_MOUNT_LOCKING
	options = SPAWN_OPT_LOCK;
#else
	options = SPAWN_OPT_NONE;
#endif

	va_start(arg, logopt);
	for (argc = 1; va_arg(arg, char *); argc++);
	va_end(arg);

	ret = readlink(_PATH_MOUNTED, buf, PATH_MAX);
	if (ret != -1) {
		buf[ret] = '\0';
		if (!strcmp(buf, _PROC_MOUNTS) ||
		    !strcmp(buf, _PROC_SELF_MOUNTS)) {
			debug(logopt,
			      "mtab link detected, passing -n to mount");
			argc++;
			update_mtab = 0;
		}
	}
	if (arg_c)
		argc++;;

	argv_len = sizeof(char *) * (argc + 1);
	argv = malloc(argv_len);
	if (!argv) {
		char buf[MAX_ERR_BUF];
		char *estr = strerror_r(errno, buf, sizeof(buf));
		crit(logopt, "malloc: %s", estr);
		return -1;
	}
	memset(argv, 0, argv_len);

	p = argv;
	*p++ = arg0;
	if (arg_c)
		*p++ = arg_c;

	if (!update_mtab)
		*p++ = argn;

	va_start(arg, logopt);
	while ((*p++ = va_arg(arg, char *)));
	va_end(arg);

	while (retries--) {
		ret = do_spawn(logopt, wait, options, prog, (const char **) argv);
		if (ret == MTAB_NOTUPDATED) {
			/*
			 * If the mount succeeded but the mtab was not
			 * updated, then retry the umount just to update
			 * the mtab.
			 */
			if (!printed) {
				debug(logopt, "umount failed with error code 16"
				      ", retrying with the -f option");
				printed = 1;
			}
		} else {
			/*
			 * umount does not support the "fake" option.  Thus,
			 * if we got a return value of MTAB_NOTUPDATED the
			 * first time, that means the umount actually
			 * succeeded.  Then, a following umount will fail
			 * due to the fact that nothing was mounted on the
			 * mount point. So, report this as success.
			 */
			if (retries < MTAB_LOCK_RETRIES - 1)
				ret = 0;
			break;
		}
	}

	/* This is not a fatal error */
	if (ret == MTAB_NOTUPDATED) {
		warn(logopt, "Unable to update the mtab file, /proc/mounts "
		     "and /etc/mtab will differ");
		ret = 0;
	}
	free(argv);

	return ret;
}

