/* ----------------------------------------------------------------------- *
 *
 *  automount.c - Linux automounter daemon
 *   
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2001-2005 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *   
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#include <dirent.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/poll.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#ifdef WITH_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "automount.h"
#if defined(LIBXML2_WORKAROUND) || defined(TIRPC_WORKAROUND)
#include <dlfcn.h>
#ifdef WITH_LDAP
#include <libxml/parser.h>
#endif
#endif

#ifndef __SWORD_TYPE
#if __WORDSIZE == 32
# define __SWORD_TYPE	int
#elif __WORDSIZE == 64
# define __SWORD_TYPE	long int
#else
#error
#endif
#endif

const char *program;		/* Initialized with argv[0] */
const char *version = VERSION_STRING;	/* Program version */
const char *libdir = AUTOFS_LIB_DIR;	/* Location of library modules */
const char *mapdir = AUTOFS_MAP_DIR;	/* Location of mount maps */
const char *confdir = AUTOFS_CONF_DIR;	/* Location of autofs config file */

unsigned int mp_mode = 0755;

unsigned int nfs_mount_uses_string_options = 0;
static struct nfs_mount_vers vers, check = {1, 1, 1};

#define FIFO_BUF_SIZE		25
static int cmd_pipe_fifo = -1;

/* autofs cmd fifo name */
#define FIFO_NAME "autofs.cmd.fifo"
const char *cmd_pipe_name = AUTOFS_FIFO_DIR "/" FIFO_NAME;

int start_cmd_pipe_handler(void);
void finish_cmd_pipe_handler(void);

const char *global_options;		/* Global option, from command line */

static char *pid_file = NULL;		/* File in which to keep pid */
unsigned int global_selection_options;

long global_negative_timeout = -1;
long global_positive_timeout = -1;
int do_force_unlink = 0;		/* Forceably unlink mount tree at startup */

static int start_pipefd[2] = {-1, -1};
static int st_stat = 1;
static int *pst_stat = &st_stat;
static pthread_t signal_handler_thid;

static sigset_t block_sigs;

/* Pre-calculated kernel packet length */
static size_t kpkt_len;

/* Attributes for creating detached and joinable threads */
pthread_attr_t th_attr;
pthread_attr_t th_attr_detached;

struct master_readmap_cond mrc = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL, 0, 0, 0, 0};

struct startup_cond suc = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0};

pthread_key_t key_thread_stdenv_vars;
pthread_key_t key_thread_attempt_id = (pthread_key_t) 0L;

int aquire_flag_file(void);
void release_flag_file(void);

extern struct master *master_list;

/* simple string hash based on public domain sdbm library */
static unsigned long sdbm_hash(const char *str, unsigned long seed)
{
	unsigned long hash = seed;
	char c;

	while ((c = *str++))
		hash = c + (hash << 6) + (hash << 16) - hash;
	return hash;
}

void set_thread_mount_request_log_id(struct pending_args *mt)
{
	char attempt_id_comp[20];
	unsigned long *attempt_id;
	int status;

	if (!defaults_get_use_mount_request_log_id())
		return;

	attempt_id = pthread_getspecific(key_thread_attempt_id);
	if (attempt_id == NULL) {
		attempt_id = (unsigned long *) calloc(1, sizeof(unsigned long));
		if (attempt_id  == NULL)
			fatal(ENOMEM);
		snprintf(attempt_id_comp, 20, "%ld", mt->wait_queue_token);
		*attempt_id = sdbm_hash(attempt_id_comp, 0);
		snprintf(attempt_id_comp, 20, "%u", mt->pid);
		*attempt_id = sdbm_hash(attempt_id_comp, *attempt_id);
		*attempt_id = sdbm_hash(mt->name, *attempt_id);
		status = pthread_setspecific(key_thread_attempt_id, attempt_id);
		if (status != 0)
			fatal(status);
	}
}

static int is_remote_fstype(unsigned int fs_type)
{
	int ret = 0;
	switch (fs_type) {
	case SMB_SUPER_MAGIC:
	case CIFS_MAGIC_NUMBER:
	case NCP_SUPER_MAGIC:
	case NFS_SUPER_MAGIC:
		ret = 1;
		break;
	};
	return ret;
}

static int do_mkdir(const char *parent, const char *path, mode_t mode)
{
	int status;
	mode_t mask;
	struct stat st, root;
	struct statfs fs;

	/* If path exists we're done */
	status = stat(path, &st);
	if (status == 0) {
		errno = EEXIST;
		if (!S_ISDIR(st.st_mode))
			errno = ENOTDIR;
		return 0;
	}

	/*
	 * We don't want to create the path on a remote file system
	 * unless it's the root file system.
	 * An empty parent means it's the root directory and always ok.
	 */
	if (*parent) {
		status = statfs(parent, &fs);
		if (status == -1)
			goto fail;

		if (is_remote_fstype(fs.f_type)) {
			status = stat(parent, &st);
			if (status == -1)
				goto fail;

			status = stat("/", &root);
			if (status == -1)
				goto fail;

			if (st.st_dev != root.st_dev)
				goto fail;
		}
	}

	mask = umask(0022);
	status = mkdir(path, mode);
	(void) umask(mask);
	if (status == -1)
		goto fail;

	return 1;
fail:
	errno = EACCES;
	return 0;
}

int mkdir_path(const char *path, mode_t mode)
{
	char buf[PATH_MAX];
	char parent[PATH_MAX];
	const char *cp = path, *lcp = path;
	char *bp = buf, *pp = parent;

	*parent = '\0';

	do {
		if (cp != path && (*cp == '/' || *cp == '\0')) {
			memcpy(bp, lcp, cp - lcp);
			bp += cp - lcp;
			*bp = '\0';
			if (!do_mkdir(parent, buf, mode)) {
				if (*cp != '\0') {
					memcpy(pp, lcp, cp - lcp);
					pp += cp - lcp;
					*pp = '\0';
					lcp = cp;
					continue;
				}
				return -1;
			}
			memcpy(pp, lcp, cp - lcp);
			pp += cp - lcp;
			*pp = '\0';
			lcp = cp;
		}
	} while (*cp++ != '\0');

	return 0;
}

/* Remove as much as possible of a path */
int rmdir_path(struct autofs_point *ap, const char *path, dev_t dev)
{
	int len = strlen(path);
	char buf[PATH_MAX + 1];
	char *cp;
	int first = 1;
	struct stat st;
	struct statfs fs;

	if (len > PATH_MAX) {
		error(ap->logopt, "path longer than maximum length");
		return -1;
	}
	strcpy(buf, path);

	cp = buf + len;
	do {
		*cp = '\0';

		/*
		 *  Before removing anything, perform some sanity checks to
		 *  ensure that we are looking at files in the automount
		 *  file system.
		 */
		memset(&st, 0, sizeof(st));
		if (lstat(buf, &st) != 0) {
			crit(ap->logopt, "lstat of %s failed", buf);
			return -1;
		}

		/* Termination condition removing full path within autofs fs */
		if (st.st_dev != dev)
			return 0;

		if (statfs(buf, &fs) != 0) {
			error(ap->logopt, "could not stat fs of %s", buf);
			return -1;
		}

		if (fs.f_type != (__SWORD_TYPE) AUTOFS_SUPER_MAGIC) {
			crit(ap->logopt, "attempt to remove directory from a "
			     "non-autofs filesystem!");
			crit(ap->logopt,
			     "requester dev == %llu, \"%s\" owner dev == %llu",
			     dev, buf, st.st_dev);
			return -1;
		}
			     
		/*
		 * Last element of path may be a symbolic link; all others
		 * are directories (and the last directory element is
		 * processed first, hence the variable name)
		 */
		if (rmdir(buf) == -1) {
			if (first && errno == ENOTDIR) {
				/*
				 *  Ensure that we will only remove
				 *  symbolic links.
				 */
				if (S_ISLNK(st.st_mode)) {
					if (unlink(buf) == -1)
						return -1;
				} else {
					crit(ap->logopt,
					   "file \"%s\" is neither a directory"
					   " nor a symbolic link. mode %d",
					   buf, st.st_mode);
					return -1;
				}
			}

			/*
			 *  If we fail to remove a directory for any reason,
			 *  we need to return an error.
			 */
			return -1;
		}

		first = 0;
	} while ((cp = strrchr(buf, '/')) != NULL && cp != buf);

	return 0;
}

/* Like ftw, except fn gets called twice: before a directory is
   entered, and after.  If the before call returns 0, the directory
   isn't entered. */
static int walk_tree(const char *base, int (*fn) (struct autofs_point *ap,
						  const char *file,
						  const struct stat * st,
						  int, void *), int incl,
						  struct autofs_point *ap,
						  void *arg)
{
	char buf[PATH_MAX + 1];
	struct stat st, *pst = &st;
	int ret;

	if (!is_mounted(base, MNTS_REAL))
		ret = lstat(base, pst);
	else {
		pst = NULL;
		ret = 0;
	}

	if (ret != -1 && (fn) (ap, base, pst, 0, arg)) {
		if (S_ISDIR(st.st_mode)) {
			struct dirent **de;
			int n;

			n = scandir(base, &de, 0, alphasort);
			if (n < 0)
				return -1;

			while (n--) {
				if (strcmp(de[n]->d_name, ".") == 0 ||
				    strcmp(de[n]->d_name, "..") == 0) {
					free(de[n]);
					continue;
				}

				if (!cat_path(buf, sizeof(buf), base, de[n]->d_name)) {
					do {
						free(de[n]);
					} while (n--);
					free(de);
					return -1;
				}

				walk_tree(buf, fn, 1, ap, arg);
				free(de[n]);
			}
			free(de);
		}
		if (incl)
			(fn) (ap, base, pst, 1, arg);
	}
	return 0;
}

static int rm_unwanted_fn(struct autofs_point *ap,
			  const char *file, const struct stat *st,
			  int when, void *arg)
{
	dev_t dev = *(dev_t *) arg;
	char buf[MAX_ERR_BUF];
	struct stat newst;

	if (!st)
		return 0;

	if (when == 0) {
		if (st->st_dev != dev)
			return 0;
		return 1;
	}

	if (lstat(file, &newst)) {
		crit(ap->logopt,
		     "unable to stat file, possible race condition");
		return 0;
	}

	if (newst.st_dev != dev) {
		crit(ap->logopt,
		     "file %s has the wrong device, possible race condition",
		     file);
		return 0;
	}

	if (S_ISDIR(newst.st_mode)) {
		debug(ap->logopt, "removing directory %s", file);
		if (rmdir(file)) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn(ap->logopt,
			      "unable to remove directory %s: %s", file, estr);
			return 0;
		}
	} else if (S_ISREG(newst.st_mode)) {
		crit(ap->logopt, "attempting to remove files from a mounted "
		     "directory. file %s", file);
		return 0;
	} else if (S_ISLNK(newst.st_mode)) {
		debug(ap->logopt, "removing symlink %s", file);
		unlink(file);
	}
	return 1;
}

void rm_unwanted(struct autofs_point *ap, const char *path, int incl)
{
	walk_tree(path, rm_unwanted_fn, incl, ap, &ap->dev);
}

struct counter_args {
	unsigned int count;
	dev_t dev;
};

static int counter_fn(struct autofs_point *ap, const char *file,
		      const struct stat *st, int when, void *arg)
{
	struct counter_args *counter = (struct counter_args *) arg;

	if (!st || (S_ISLNK(st->st_mode) || (S_ISDIR(st->st_mode)
		&& st->st_dev != counter->dev))) {
		counter->count++;
		return 0;
	}

	return 1;
}

/* Count mounted filesystems and symlinks */
int count_mounts(struct autofs_point *ap, const char *path, dev_t dev)
{
	struct counter_args counter;

	counter.count = 0;
	counter.dev = dev;
	
	if (walk_tree(path, counter_fn, 1, ap, &counter) == -1)
		return -1;

	return counter.count;
}

static void check_rm_dirs(struct autofs_point *ap, const char *path, int incl)
{
	/*
	 * If we're a submount the kernel can't know we're trying to
	 * shutdown and so cannot block processes walking into the
	 * mount point directory. If this is the call to umount_multi()
	 * made during shutdown (incl == 0) we have to leave any mount
	 * point directories in place so we can recover if needed. The
	 * umount itself will clean these directories up for us
	 * automagically.
	 */
	if (!incl && ap->submount)
		return;

	if ((!(ap->flags & MOUNT_FLAG_GHOST)) ||
	    (ap->state == ST_SHUTDOWN_PENDING ||
	     ap->state == ST_SHUTDOWN_FORCE ||
	     ap->state == ST_SHUTDOWN))
		rm_unwanted(ap, path, incl);
	else if ((ap->flags & MOUNT_FLAG_GHOST) && (ap->type == LKP_INDIRECT))
		rm_unwanted(ap, path, 0);
}

/* Try to purge cache entries kept around due to existing mounts */
static void update_map_cache(struct autofs_point *ap, const char *path)
{
	struct map_source *map;
	struct mapent_cache *mc;
	const char *key;

	if (ap->type == LKP_INDIRECT)
		key = strrchr(path, '/') + 1;
	else
		key = path;

	map = ap->entry->maps;
	while (map) {
		struct mapent *me = NULL;

		/* Skip current, in-use cache */
		if (ap->entry->age <= map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		/* If the lock is busy try later */
		if (cache_try_writelock(mc)) {
			me = cache_lookup_distinct(mc, key);
			if (me && me->ioctlfd == -1)
				cache_delete(mc, key);
			cache_unlock(mc);
		}

		map = map->next;
	}

	return;
}

static int umount_subtree_mounts(struct autofs_point *ap, const char *path, unsigned int is_autofs_fs)
{
	struct mapent_cache *mc;
	struct mapent *me;
	unsigned int is_mm_root = 0;
	int cur_state;
	int left;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);

	me = lookup_source_mapent(ap, path, LKP_DISTINCT);
	if (!me) {
		char *ind_key;

		ind_key = strrchr(path, '/');
		if (ind_key)
			ind_key++;

		me = lookup_source_mapent(ap, ind_key, LKP_NORMAL);
	}

	if (me) {
		mc = me->mc;
		is_mm_root = IS_MM_ROOT(me);
	}

	left = 0;

	if (me && IS_MM(me)) {
		char key[PATH_MAX + 1];
		struct mapent *tmp;
		int ret;

		ret = tree_mapent_umount_offsets(me);
		if (!ret) {
			warn(ap->logopt,
			     "some offset mounts still present under %s", path);
			left++;
		}

		if (me->len > PATH_MAX) {
			crit(ap->logopt, "me->key too long for buffer");
			return 1;
		}

		strcpy(key, me->key);

		cache_unlock(mc);
		cache_writelock(mc);
		tmp = cache_lookup_distinct(mc, key);
		/* mapent went away while we waited? */
		if (tmp != me) {
			cache_unlock(mc);
			pthread_setcancelstate(cur_state, NULL);
			return 0;
		}

		if (!left && IS_MM_ROOT(me)) {
			if (!tree_mapent_delete_offsets(mc, me->key)) {
				warn(ap->logopt, "couldn't delete offset list");
				left++;
			}
		}

		if (ap->entry->maps &&
		    (ap->entry->maps->flags & MAP_FLAG_FORMAT_AMD))
			cache_pop_mapent(me);
	}
	if (me)
		cache_unlock(mc);

	pthread_setcancelstate(cur_state, NULL);

	if (left || is_autofs_fs)
		return left;

	/*
	 * If this is the root of a multi-mount we've had to umount
	 * it already to ensure it's ok to remove any offset triggers.
	 */
	if (!is_mm_root && is_mounted(path, MNTS_REAL)) {
		struct mnt_list *mnt;

		debug(ap->logopt, "unmounting dir = %s", path);
		if (umount_ent(ap, path)) {
			warn(ap->logopt, "could not umount dir %s", path);
			left++;
			goto done;
		}

		/* Check for an external mount and umount if possible */
		mnt = mnts_find_amdmount(path);
		if (mnt) {
			umount_amd_ext_mount(ap, mnt->ext_mp);
			mnts_remove_amdmount(path);
			mnts_put_mount(mnt);
		}
	}
done:
	return left;
}

/* umount all filesystems mounted under path.  If incl is true, then
   it also tries to umount path itself */
int umount_multi(struct autofs_point *ap, const char *path, int incl)
{
	struct mnt_list *sbmnt;
	int is_autofs_fs;
	struct stat st;
	int left;

	debug(ap->logopt, "path %s incl %d", path, incl);

	if (lstat(path, &st)) {
		warn(ap->logopt,
		     "failed to stat directory or symlink %s", path);
		return 1;
	}

	/* if this is a symlink we can handle it now */
	if (S_ISLNK(st.st_mode)) {
		struct mnt_list *mnt;

		if (st.st_dev != ap->dev) {
			crit(ap->logopt,
			     "symlink %s has the wrong device, "
			     "possible race condition", path);
			return 1;
		}
		debug(ap->logopt, "removing symlink %s", path);
		if (unlink(path)) {
			error(ap->logopt,
			      "failed to remove symlink %s", path);
			return 1;
		}

		/* Check if the autofs mount has browse mode enabled.
		 * If so re-create the directory entry.
		 */
		if (ap->flags & MOUNT_FLAG_GHOST) {
			int ret;

			/* If the browse directory create fails log an
			 * error and continue anyway since the expire
			 * has succeeded.
			 */
			ret = mkdir_path(path, mp_mode);
			if (ret && errno != EEXIST) {
				char buf[MAX_ERR_BUF];
				char *estr;
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				warn(ap->logopt,
				     "mkdir_path %s failed: %s", path, estr);
			}
		}

		/* Check for an external mount and attempt umount if needed */
		mnt = mnts_find_amdmount(path);
		if (mnt) {
			umount_amd_ext_mount(ap, mnt->ext_mp);
			mnts_remove_amdmount(path);
			mnts_put_mount(mnt);
		}

		/* Check for mounted mount and remove it if found */
		mnts_remove_mount(path, MNTS_MOUNTED);

		return 0;
	}

	is_autofs_fs = 0;
	sbmnt = mnts_find_submount(path);
	if (sbmnt) {
		is_autofs_fs = 1;
		mnts_put_mount(sbmnt);
	}

	left = 0;

	left += umount_subtree_mounts(ap, path, is_autofs_fs);

	/* Delete detritus like unwanted mountpoints and symlinks */
	if (left == 0 &&
	    ap->state != ST_READMAP &&
	    !count_mounts(ap, path, ap->dev)) {
		update_map_cache(ap, path);
		check_rm_dirs(ap, path, incl);
	}

	return left;
}

static void umount_all(struct autofs_point *ap)
{
	int left;

	left = umount_multi(ap, ap->path, 0);
	if (left)
		warn(ap->logopt, "could not unmount %d dirs under %s",
		     left, ap->path);
}

static int umount_autofs(struct autofs_point *ap)
{
	int ret = 0;

	if (ap->state == ST_INIT)
		return -1;

	if (ap->type == LKP_INDIRECT) {
		umount_all(ap);
		ret = umount_autofs_indirect(ap);
	} else
		ret = umount_autofs_direct(ap);

	return ret;
}

static size_t get_kpkt_len(void)
{
	size_t pkt_len = sizeof(struct autofs_v5_packet);
	struct utsname un;
	int kern_vers;

	kern_vers = linux_version_code();
	if (kern_vers >= KERNEL_VERSION(3, 3, 0))
		return pkt_len;

	uname(&un);

	if (pkt_len % 8) {
		if (strcmp(un.machine, "alpha") == 0 ||
		    strcmp(un.machine, "ia64") == 0 ||
		    strcmp(un.machine, "x86_64") == 0 ||
		    strcmp(un.machine, "parisc64") == 0 ||
		    strcmp(un.machine, "ppc64") == 0)
			pkt_len += 4;

	}

	return pkt_len;
}

static int fullread(int fd, void *ptr, size_t len)
{
	char *buf = (char *) ptr;

	while (len > 0) {
		ssize_t r = read(fd, buf, len);

		if (r == -1) {
			if (errno == EINTR)
				continue;
			break;
		}

		buf += r;
		len -= r;
	}

	return len;
}

static void dummy(int sig)
{
}

static int get_pkt(struct autofs_point *ap, union autofs_v5_packet_union *pkt)
{
	struct sigaction sa;
	sigset_t signalset;
	struct pollfd fds[1];
	int pollfds = 1;
	char buf[MAX_ERR_BUF];
	size_t read;
	char *estr;

	fds[0].fd = ap->pipefd;
	fds[0].events = POLLIN;

	sa.sa_handler = dummy;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGCONT, &sa, NULL) == -1)
		error(LOGOPT_ANY, "failed to set signal handler %d", errno);

	sigfillset(&signalset);
	sigdelset(&signalset, SIGCONT);

	for (;;) {
		errno = 0;
		if (ppoll(fds, pollfds, NULL, &signalset) == -1) {
			if (errno == EINTR) {
				st_mutex_lock();
				if (ap->state == ST_SHUTDOWN) {
					st_mutex_unlock();
					return -1;
				}
				st_mutex_unlock();
				continue;
			}
			estr = strerror_r(errno, buf, MAX_ERR_BUF);
			logerr("poll failed: %s", estr);
			return -1;
		}

		if (fds[0].revents & POLLIN) {
			read = fullread(ap->pipefd, pkt, kpkt_len);
			if (read) {
				estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(ap->logopt,
				      "read error on request pipe, "
				      "read %lu, expected %lu error %s",
				       read, kpkt_len, estr);
			}
			return read;
		}
	}
}

int do_expire(struct autofs_point *ap, const char *name, int namelen)
{
	char buf[PATH_MAX];
	const char *parent;
	int len, ret;

	if (*name != '/') {
		len = ncat_path(buf, sizeof(buf), ap->path, name, namelen);
		parent = ap->path;
	} else {
		len = snprintf(buf, PATH_MAX, "%s", name);
		if (len >= PATH_MAX)
			len = 0;
		parent = name;
	}

	if (!len) {
		crit(ap->logopt, "path too long for buffer");
		return 1;
	}

	info(ap->logopt, "expiring path %s on %s", buf, parent);

	pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
	master_source_readlock(ap->entry);
	ret = umount_multi(ap, buf, 1);
	if (ret == 0)
		info(ap->logopt, "umounting %s succeeded", buf);
	else
		warn(ap->logopt, "couldn't complete expire of %s", buf);
	pthread_cleanup_pop(1);

	return ret;
}

static int autofs_init_ap(struct autofs_point *ap)
{
	int pipefd[2];

	if ((ap->state != ST_INIT)) {
		/* This can happen if an autofs process is already running*/
		error(ap->logopt, "bad state %d", ap->state);
		return -1;
	}

	ap->pipefd = ap->kpipefd = ap->ioctlfd = -1;

	/* Pipe for kernel communications */
	if (open_pipe(pipefd) < 0) {
		crit(ap->logopt,
		     "failed to create commumication pipe for autofs path %s",
		     ap->path);
		return -1;
	}

	ap->pipefd = pipefd[0];
	ap->kpipefd = pipefd[1];

	return 0;
}

static int mount_autofs(struct autofs_point *ap)
{
	int status;

	/* No need to create comms fds and command fifo if
	 * unlinking mounts and exiting.
	 */
	if (!(do_force_unlink & UNLINK_AND_EXIT)) {
		if (autofs_init_ap(ap) != 0)
			return -1;
	}

	if (ap->type == LKP_DIRECT)
		status = mount_autofs_direct(ap);
	else
		status = mount_autofs_indirect(ap);

	st_add_task(ap, ST_READY);

	return status;
}

static int handle_packet(struct autofs_point *ap)
{
	union autofs_v5_packet_union pkt;

	if (get_pkt(ap, &pkt))
		return -1;

	debug(ap->logopt, "type = %d", pkt.hdr.type);

	switch (pkt.hdr.type) {
	case autofs_ptype_missing_indirect:
		return handle_packet_missing_indirect(ap, &pkt.v5_packet);

	case autofs_ptype_missing_direct:
		return handle_packet_missing_direct(ap, &pkt.v5_packet);

	case autofs_ptype_expire_indirect:
		return handle_packet_expire_indirect(ap, &pkt.v5_packet);

	case autofs_ptype_expire_direct:
		return handle_packet_expire_direct(ap, &pkt.v5_packet);
	}
	error(ap->logopt, "unknown packet type %d", pkt.hdr.type);
	return -1;
}

static void become_daemon(unsigned int flags)
{
	FILE *pidfp;
	char buf[MAX_ERR_BUF];
	int res;
	pid_t pid;

	/* Don't BUSY any directories unnecessarily */
	if (chdir("/")) {
		fprintf(stderr, "%s: failed change working directory.\n",
			program);
		exit(0);
	}

	/* Detach from foreground process */
	if (flags & DAEMON_FLAGS_FOREGROUND &&
	   !(flags & DAEMON_FLAGS_SYSTEMD_SERVICE)) {
		if ((flags & DAEMON_FLAGS_CHECK_DAEMON) && !aquire_flag_file()) {
			fprintf(stderr, "%s: program is already running.\n",
				program);
			exit(1);
		}
		log_to_stderr();
	} else if (flags & DAEMON_FLAGS_SYSTEMD_SERVICE) {
		if ((flags & DAEMON_FLAGS_CHECK_DAEMON) && !aquire_flag_file()) {
			fprintf(stderr, "%s: program is already running.\n",
				program);
			exit(1);
		}
		open_log();
	} else {
		int nullfd;

		if (open_pipe(start_pipefd) < 0) {
			fprintf(stderr, "%s: failed to create start_pipefd.\n",
				program);
			exit(0);
		}

		pid = fork();
		if (pid > 0) {
			close(start_pipefd[1]);
			res = read(start_pipefd[0], pst_stat, sizeof(*pst_stat));
			if (res < 0)
				exit(1);
			exit(*pst_stat);
		} else if (pid < 0) {
			fprintf(stderr, "%s: Could not detach process\n",
				program);
			exit(1);
		}
		close(start_pipefd[0]);

		if ((flags & DAEMON_FLAGS_CHECK_DAEMON) && !aquire_flag_file()) {
			fprintf(stderr, "%s: program is already running.\n",
				program);
			/* Return success if already running */
			st_stat = 0;
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			if (res < 0)
				exit(1);
			close(start_pipefd[1]);
			exit(*pst_stat);
		}

		/*
		 * Make our own process group for "magic" reason: processes that share
		 * our pgrp see the raw filesystem behind the magic.
		 */
		if (setsid() == -1) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			fprintf(stderr, "setsid: %s", estr);
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
			exit(*pst_stat);
		}

		/* Redirect all our file descriptors to /dev/null */
		nullfd = open("/dev/null", O_RDWR);
		if (nullfd < 0) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			fprintf(stderr, "cannot open /dev/null: %s", estr);
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
			exit(*pst_stat);
		}

		if (dup2(nullfd, STDIN_FILENO) < 0 ||
		    dup2(nullfd, STDOUT_FILENO) < 0 ||
		    dup2(nullfd, STDERR_FILENO) < 0) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			fprintf(stderr,
				"redirecting file descriptors failed: %s", estr);
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
			exit(*pst_stat);
		}

		open_log();
		close(nullfd);
	}

	/* Write pid file if requested */
	if (pid_file) {
		if ((pidfp = fopen(pid_file, "wt"))) {
			fprintf(pidfp, "%lu\n", (unsigned long) getpid());
			fclose(pidfp);
		} else {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			logerr("failed to write pid file %s: %s",
			       pid_file, estr);
			pid_file = NULL;
		}
	}
}

static unsigned long getnumopt(char *str, char option)
{
	unsigned long val;
	char *end;

	val = strtoul(str, &end, 0);
	if (!*str || *end) {
		fprintf(stderr,
			"%s: option -%c requires a numeric argument, got %s\n",
			program, option, str);
		exit(1);
	}
	return val;
}

static long getsnumopt(char *str, char option)
{
	long val;
	char *end;

	val = strtol(str, &end, 0);
	if (!*str || *end) {
		fprintf(stderr,
			"%s: option -%c requires a numeric argument, got %s\n",
			program, option, str);
		exit(1);
	}
	return val;
}

static void do_master_cleanup_unlock(void *arg)
{
	int status;

	status = pthread_mutex_unlock(&mrc.mutex);
	if (status)
		fatal(status);

	return;
}

static void *do_notify_state(void *arg)
{
	struct master *master;
	int sig;
	int status;

	sig = *(int *) arg;

	status = pthread_mutex_lock(&mrc.mutex);
	if (status)
		fatal(status);

	master = mrc.master;

	debug(master->logopt, "signal %d", sig);

	mrc.signaled = 1;
	status = pthread_cond_signal(&mrc.cond);
	if (status) {
		error(master->logopt,
		      "failed to signal state notify condition");
		status = pthread_mutex_unlock(&mrc.mutex);
		if (status)
			fatal(status);
		pthread_exit(NULL);
	}

	status = pthread_mutex_unlock(&mrc.mutex);
	if (status)
		fatal(status);

	master_notify_state_change(master, sig);

	return NULL;
}

static pthread_t do_signals(struct master *master, int sig)
{
	pthread_t thid;
	int r_sig = sig;
	int status;

	status = pthread_mutex_lock(&mrc.mutex);
	if (status)
		fatal(status);

	status = pthread_create(&thid, &th_attr_detached, do_notify_state, &r_sig);
	if (status) {
		error(master->logopt,
		      "mount state notify thread create failed");
		status = pthread_mutex_unlock(&mrc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	mrc.thid = thid;
	mrc.master = master;

	pthread_cleanup_push(do_master_cleanup_unlock, NULL);

	mrc.signaled = 0;
	while (!mrc.signaled) {
		status = pthread_cond_wait(&mrc.cond, &mrc.mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return thid;
}

static void *do_read_master(void *arg)
{
	struct master *master;
	unsigned int logopt;
	time_t age;
	int status;

	status = pthread_mutex_lock(&mrc.mutex);
	if (status)
		fatal(status);

	master = mrc.master;
	age = mrc.age;
	logopt = master->logopt;

	mrc.signaled = 1;
	status = pthread_cond_signal(&mrc.cond);
	if (status) {
		error(logopt,
		      "failed to signal master read map condition");
		master->reading = 0;
		status = pthread_mutex_unlock(&mrc.mutex);
		if (status)
			fatal(status);
		pthread_exit(NULL);
	}

	status = pthread_mutex_unlock(&mrc.mutex);
	if (status)
		fatal(status);

	if (!defaults_read_config(1)) {
		error(logopt, "failed to read configuration, exiting");
		master->reading = 0;
		pthread_exit(NULL);
	}

	info(logopt, "re-reading master map %s", master->name);

	master->readall = 1;

	status = master_read_master(master, age);

	master->readall = 0;
	master->reading = 0;

	return NULL;
}

static int do_hup_signal(struct master *master)
{
	unsigned int logopt = master->logopt;
	time_t age = monotonic_time(NULL);
	pthread_t thid;
	int status;

	status = pthread_mutex_lock(&mrc.mutex);
	if (status)
		fatal(status);

	nfs_mount_uses_string_options = check_nfs_mount_version(&vers, &check);

	master_mutex_lock();
	/* Already doing a map read or shutdown or no mounts */
	if (master->reading) {
		status = pthread_mutex_unlock(&mrc.mutex);
		if (status)
			fatal(status);
		master_mutex_unlock();
		return 1;
	}
	master->reading = 1;
	master_mutex_unlock();

	status = pthread_create(&thid, &th_attr_detached, do_read_master, NULL);
	if (status) {
		error(logopt,
		      "master read map thread create failed");
		master->reading = 0;
		status = pthread_mutex_unlock(&mrc.mutex);
		if (status)
			fatal(status);
		return 0;
	}

	mrc.thid = thid;
	mrc.master = master;
	mrc.age = age;

	pthread_cleanup_push(do_master_cleanup_unlock, NULL);

	mrc.signaled = 0;
	while (!mrc.signaled) {
		status = pthread_cond_wait(&mrc.cond, &mrc.mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return 1;
}

/* Deal with all the signal-driven events in the state machine */
static void *signal_handler(void *arg)
{
	sigset_t signalset;
	int sig;

	memcpy(&signalset, &block_sigs, sizeof(signalset));
	sigdelset(&signalset, SIGCHLD);
	sigdelset(&signalset, SIGCONT);

	while (1) {
		sigwait(&signalset, &sig);

		switch (sig) {
		case SIGTERM:
		case SIGINT:
		case SIGUSR2:
			master_mutex_lock();
			if (list_empty(&master_list->completed)) {
				if (__master_list_empty(master_list)) {
					master_mutex_unlock();
					return NULL;
				}
			} else {
				if (master_done(master_list)) {
					master_mutex_unlock();
					return NULL;
				}
				master_mutex_unlock();
				break;
			}
			master_mutex_unlock();

		case SIGUSR1:
			do_signals(master_list, sig);
			break;

		case SIGHUP:
			do_hup_signal(master_list);
			break;

		default:
			logerr("got unexpected signal %d!", sig);
			continue;
		}
	}
}

static pthread_mutex_t cmd_pipe_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int done = 0;
static pthread_t cmd_pipe_thid;

void cmd_pipe_mutex_lock(void)
{
	int status = pthread_mutex_lock(&cmd_pipe_mutex);
	if (status)
		fatal(status);
}

void cmd_pipe_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&cmd_pipe_mutex);
	if (status)
		fatal(status);
}

static int create_cmd_pipe_fifo(void)
{
	char buf[MAX_ERR_BUF];
	int ret = -1;
	int fd;

	if (cmd_pipe_fifo != -1)
		return 0;

	ret = unlink(cmd_pipe_name);
	if (ret != 0 && errno != ENOENT) {
		fprintf(stderr,
			"%s: failed to unlink command pipe. Is the "
			"automount daemon already running?", program);
		return ret;
	}

	ret = mkfifo(cmd_pipe_name, S_IRUSR|S_IWUSR);
	if (ret != 0 && errno != EEXIST) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		fprintf(stderr, "%s: mkfifo for %s failed: %s",
			program, cmd_pipe_name, estr);
		return ret;
	}

	fd = open_fd(cmd_pipe_name, O_RDWR|O_NONBLOCK);
	if (fd < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		unlink(cmd_pipe_name);
		fprintf(stderr, "%s: failed to open command pipe %s: %s",
			program, cmd_pipe_name, estr);
		return -1;
	}

	cmd_pipe_fifo = fd;

	return 0;
}

static int destroy_cmd_pipe_fifo(void)
{
	char buf[MAX_ERR_BUF];
	int ret = -1;

	if (cmd_pipe_fifo == -1)
		return 0;

	ret = close(cmd_pipe_fifo);
	if (ret != 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		warn(LOGOPT_ANY,
		     "close for command pipe %s: %s", cmd_pipe_name, estr);
	}

	cmd_pipe_fifo = -1;

	ret = unlink(cmd_pipe_name);
	if (ret != 0) {
		warn(LOGOPT_ANY,
		     "failed to unlink FIFO. Was the fifo created OK?");
	}

	return 0;
}

static void handle_cmd_pipe_fifo_message(int fd)
{
	struct autofs_point *ap;
	char buffer[PIPE_BUF];
	char *end, *sep;
	char buf[MAX_ERR_BUF];
	dev_t devid;
	int ret;
	long pri;

	ret = read(fd, &buffer, sizeof(buffer));
	if (ret < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		warn(LOGOPT_ANY,
		     "read on command pipe returned error: %s", estr);
		return;
	}
	if (ret >= sizeof(buffer)) {
		error(LOGOPT_ANY,
		      "read overrun on command pipe message");
		return;
	}
	buffer[ret] = 0;

	sep = strrchr(buffer, ' ');
	if (!sep) {
		error(LOGOPT_ANY,
		      "incorrect command pipe message format %s.", buffer);
		return;
	}
	sep++;

	errno = 0;
	devid = strtol(buffer, &end, 10);
	if ((devid == LONG_MIN || devid == LONG_MAX) && errno == ERANGE) {
		debug(LOGOPT_ANY, "strtol reported a range error.");
		error(LOGOPT_ANY, "invalid command pipe message format %s.", buffer);
		return;
	}

	if ((devid == 0 && errno == EINVAL) || end == buffer) {
		debug(LOGOPT_ANY, "devid id is expected to be a integer.");
		return;
	}

	ap = master_find_mapent_by_devid(master_list, devid);
	if (!ap) {
		error(LOGOPT_ANY, "can't locate autofs_point for device id %ld.", devid);
		return;
	}

	errno = 0;
	pri = strtol(sep, &end, 10);
	if ((pri == LONG_MIN || pri == LONG_MAX) && errno == ERANGE) {
		error(ap->logopt, "failed to set log priority.");
		error(ap->logopt, "strtol reported an %s.",
		      pri == LONG_MIN ? "underflow" : "overflow");
		return;
	}

	if ((pri == 0 && errno == EINVAL) || end == sep) {
		debug(ap->logopt, "priority is expected to be an integer "
		      "in the range 0-7 inclusive.");
		return;
	}

	if (pri > LOG_DEBUG || pri < LOG_EMERG) {
		debug(ap->logopt,
		      "invalid log priority (%ld) received on fifo", pri);
		return;
	}

	/*
	 * OK, the message passed all of the sanity checks.  The
	 * automounter actually only supports three log priorities.
	 * Everything is logged at log level debug, deamon messages
	 * and everything except debug messages are logged with the
	 * verbose setting and only error and critical messages are
	 * logged when debugging isn't enabled.
	 */
	if (pri >= LOG_WARNING) {
		if (pri == LOG_DEBUG) {
			set_log_debug_ap(ap);
			info(ap->logopt, "debug logging set for %s", ap->path);
		} else {
			set_log_verbose_ap(ap);
			info(ap->logopt, "verbose logging set for %s", ap->path);
		}
	} else {
		if (ap->logopt & LOGOPT_ANY)
			info(ap->logopt, "basic logging set for %s", ap->path);
		set_log_norm_ap(ap);
	}
}

static int set_log_priority(const char *path, int priority)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	char buf[FIFO_BUF_SIZE];
	dev_t devid;
	int fd;
	int ret;

	if (!ops) {
		fprintf(stderr, "Could not get ioctl ops\n");
		return -1;
	} else {
		ret = ops->mount_device(LOGOPT_ANY, path, 0, &devid);
		if (ret == -1 || ret == 0) {
			fprintf(stderr,
				"Could not find device id for mount %s\n", path);
			return -1;
		}
	}

	if (priority > LOG_DEBUG || priority < LOG_EMERG) {
		fprintf(stderr, "Log priority %d is invalid.\n", priority);
		fprintf(stderr, "Please specify a number in the range 0-7.\n");
		return -1;
	}

	/*
	 * This is an ascii based protocol, so we want the string
	 * representation of the integer log priority.
	 */
	ret = snprintf(buf, sizeof(buf), "%ld %d", devid, priority);
	if (ret >= FIFO_BUF_SIZE) {
		fprintf(stderr, "Invalid device id or log priotity\n");
		return -1;
	}

	/*
	 * Specify O_NONBLOCK so that the open will fail if there is no
	 * daemon reading from the other side of the FIFO.
	 */
	fd = open_fd(cmd_pipe_name, O_WRONLY|O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "%s: open of %s failed with %s\n",
			__FUNCTION__, cmd_pipe_name, strerror(errno));
		fprintf(stderr, "%s: perhaps the fifo wasn't setup,"
			" please check your log for more information\n", __FUNCTION__);
		return -1;
	}

	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		fprintf(stderr, "Failed to change logging priority.  ");
		fprintf(stderr, "write to fifo failed: %s.\n",
			strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	fprintf(stdout, "Successfully set log priority for %s.\n", path);

	return 0;
}

static void cmd_pipe_dummy(int sig)
{
}

static void *cmd_pipe_handler(void *arg)
{
	struct sigaction sa;
	sigset_t signalset;
	struct pollfd fds[1];
	int pollfds = 1;
	char buf[MAX_ERR_BUF];
	char *estr;

	if (create_cmd_pipe_fifo())
		return NULL;

	fds[0].fd = cmd_pipe_fifo;
	fds[0].events = POLLIN;

	sa.sa_handler = cmd_pipe_dummy;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		error(LOGOPT_ANY, "failed to set signal handler %d", errno);
		return NULL;
	}

	sigfillset(&signalset);
	sigdelset(&signalset, SIGPIPE);

	while (1) {
		cmd_pipe_mutex_lock();
		if (done)
			break;
		cmd_pipe_mutex_unlock();

		errno = 0;
		if (ppoll(fds, pollfds, NULL, &signalset) == -1) {
			if (errno == EINTR)
				continue;
			cmd_pipe_mutex_lock();
			estr = strerror_r(errno, buf, MAX_ERR_BUF);
			logerr("poll failed: %s", estr);
			break;
		}

		if (fds[0].revents & POLLIN) {
			debug(LOGOPT_ANY, "message pending on control fifo.");
			handle_cmd_pipe_fifo_message(fds[0].fd);
		}
	}
	destroy_cmd_pipe_fifo();
	cmd_pipe_mutex_unlock();
	return NULL;
}

int start_cmd_pipe_handler(void)
{
	pthread_t thid;
	pthread_attr_t attrs;
	pthread_attr_t *pattrs = &attrs;
	int status;

	status = pthread_attr_init(pattrs);
	if (status)
		pattrs = NULL;
	else
		pthread_attr_setdetachstate(pattrs, PTHREAD_CREATE_DETACHED);

	status = pthread_create(&thid, pattrs, cmd_pipe_handler, NULL);

	if (pattrs)
		pthread_attr_destroy(pattrs);

	if (!status)
		cmd_pipe_thid = thid;

	return !status;
}

void finish_cmd_pipe_handler(void)
{
	cmd_pipe_mutex_lock();
	if (cmd_pipe_thid == -1 || done)
	       goto exit;
	done = 1;
	pthread_kill(cmd_pipe_thid, SIGPIPE);
exit:
	cmd_pipe_mutex_unlock();
}

static void return_start_status(void *arg)
{
	struct startup_cond *sc;
	int status;

	sc = (struct startup_cond *) arg;

	sc->done = 1;

	/*
	 * Startup condition mutex must be locked during 
	 * the startup process.
	 */
	status = pthread_cond_signal(&sc->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&sc->mutex);
	if (status)
		fatal(status);
}

int handle_mounts_startup_cond_init(struct startup_cond *suc)
{
	int status;

	status = pthread_mutex_init(&suc->mutex, NULL);
	if (status)
		return status;

	status = pthread_cond_init(&suc->cond, NULL);
	if (status) {
		status = pthread_mutex_destroy(&suc->mutex);
		if (status)
			fatal(status);
		return status;
	}

	status = pthread_mutex_lock(&suc->mutex);
	if (status) {
		status = pthread_mutex_destroy(&suc->mutex);
		if (status)
			fatal(status);
		status = pthread_cond_destroy(&suc->cond);
		if (status)
			fatal(status);
	}

	return 0;
}

void handle_mounts_startup_cond_destroy(void *arg)
{
	struct startup_cond *suc = (struct startup_cond *) arg;
	int status;

	status = pthread_mutex_unlock(&suc->mutex);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&suc->mutex);
	if (status)
		fatal(status);

	status = pthread_cond_destroy(&suc->cond);
	if (status)
		fatal(status);

	return;
}

static void handle_mounts_cleanup(void *arg)
{
	struct autofs_point *ap;
	char buf[MAX_ERR_BUF];
	unsigned int clean = 0, submount, logopt;
	unsigned int pending = 0;

	ap = (struct autofs_point *) arg;

	logopt = ap->logopt;
	submount = ap->submount;

	if (!submount && strcmp(ap->path, "/-") &&
	    ap->flags & MOUNT_FLAG_DIR_CREATED)
		clean = 1;

	if (submount) {
		struct mnt_list *mnt;

		/* Submount at ap->path belongs to parent submount list. */
		mnts_remove_submount(ap->path);
		/* Also remove from parent mounted list */
		mnts_remove_mount(ap->path, MNTS_MOUNTED);
		mnt = mnts_find_amdmount(ap->path);
		if (mnt) {
			mnts_remove_amdmount(ap->path);
			mnts_put_mount(mnt);
		}
	}

	/* Don't signal the handler if we have already done so */
	if (!list_empty(&master_list->completed))
		pending = 1;

	info(logopt, "shut down path %s", ap->path);

	if (clean) {
		if (rmdir(ap->path) == -1) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn(logopt, "failed to remove dir %s: %s",
			     ap->path, estr);
		}
	}

	master_remove_mapent(ap->entry);
	master_source_unlock(ap->entry);

	/*
	 * Send a signal to the signal handler so it can join with any
	 * completed handle_mounts() threads and perform final cleanup.
	 */
	if (!pending)
		pthread_kill(signal_handler_thid, SIGTERM);

	master_mutex_unlock();

	return;
}

int handle_mounts_exit(struct autofs_point *ap)
{
	int ret, cur_state;

	/*
	 * If we're a submount we need to ensure our parent
	 * doesn't try to mount us again until our shutdown
	 * is complete and that any outstanding mounts are
	 * completed before we try to shutdown.
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);

	master_mutex_lock();

	master_source_writelock(ap->entry);

	if (ap->state != ST_SHUTDOWN) {
		conditional_alarm_add(ap, ap->exp_runfreq);
		/* Return to ST_READY is done immediately */
		st_add_task(ap, ST_READY);
		master_source_unlock(ap->entry);
		master_mutex_unlock();

		pthread_setcancelstate(cur_state, NULL);
		return 0;
	}

	alarm_delete(ap);
	st_remove_tasks(ap);
	st_wait_task(ap, ST_ANY, 0);

	/*
	 * For a direct mount map all mounts have already gone
	 * by the time we get here and since we only ever
	 * umount direct mounts at shutdown there is no need
	 * to check for possible recovery.
	 */
	if (ap->type == LKP_DIRECT) {
		umount_autofs(ap);
		handle_mounts_cleanup(ap);
		return 1;
	}

	/*
	 * If umount_autofs returns non-zero it wasn't able
	 * to complete the umount and has left the mount intact
	 * so we can continue. This can happen if a lookup
	 * occurs while we're trying to umount.
	 */
	ret = umount_autofs(ap);
	if (!ret) {
		set_indirect_mount_tree_catatonic(ap);
		handle_mounts_cleanup(ap);
		return 1;
	}

	/* Failed shutdown returns to ready */
	warn(ap->logopt, "can't shutdown: filesystem %s still busy", ap->path);
	conditional_alarm_add(ap, ap->exp_runfreq);
	/* Return to ST_READY is done immediately */
	st_add_task(ap, ST_READY);
	master_source_unlock(ap->entry);
	master_mutex_unlock();

	pthread_setcancelstate(cur_state, NULL);

	return 0;
}

void *handle_mounts(void *arg)
{
	struct startup_cond *suc;
	struct autofs_point *ap;
	int cancel_state, status = 0;

	suc = (struct startup_cond *) arg;

	ap = suc->ap;

	pthread_cleanup_push(return_start_status, suc);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	status = pthread_mutex_lock(&suc->mutex);
	if (status) {
		logerr("failed to lock startup condition mutex!");
		fatal(status);
	}

	if (mount_autofs(ap) < 0) {
		if (!(do_force_unlink & UNLINK_AND_EXIT))
			crit(ap->logopt, "mount of %s failed!", ap->path);
		suc->status = 1;
		umount_autofs(ap);
		pthread_setcancelstate(cancel_state, NULL);
		pthread_exit(NULL);
	}

	if (ap->flags & MOUNT_FLAG_NOBIND)
		info(ap->logopt, "bind mounts disabled");

	if (ap->flags & MOUNT_FLAG_GHOST && ap->type != LKP_DIRECT)
		info(ap->logopt, "ghosting enabled");

	suc->status = 0;
	pthread_cleanup_pop(1);

	pthread_setcancelstate(cancel_state, NULL);

	while (1) {
		if (handle_packet(ap)) {
			if (handle_mounts_exit(ap))
				break;
		}

		/* If we get here a packet has been received and handled
		 * and the autofs mount point has not been shutdown. But
		 * if the autofs mount point has been set to ST_SHUTDOWN
		 * we should attempt to perform the shutdown cleanup and
		 * exit if successful.
		 */
		if (ap->state == ST_SHUTDOWN) {
			if (handle_mounts_exit(ap))
				break;
		}
	}

	return NULL;
}

static void key_thread_stdenv_vars_destroy(void *arg)
{
	struct thread_stdenv_vars *tsv;

	tsv = (struct thread_stdenv_vars *) arg;
	if (tsv->user)
		free(tsv->user);
	if (tsv->group)
		free(tsv->group);
	if (tsv->home)
		free(tsv->home);
	free(tsv);
	return;
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: %s [options] [master_map_name]\n"
		"	-h --help	this text\n"
		"	-p --pid-file f write process id to file f\n"
		"	-t --timeout n	auto-unmount in n seconds (0-disable)\n"
		"	-M --master-wait n\n"
	        "			maximum wait time (seconds) for master\n"
	        "			map to become available\n"
		"	-v --verbose	be verbose\n"
		"	-d[level]\n"
		"	--debug[=level]\n"
		"			log debugging info\n"
		"	-Dvariable=value, --define variable=value\n"
		"			define global macro variable\n"
		"	-S --systemd-service\n"
		"			run automounter as a systemd service\n"
		"	-f --foreground do not fork into background\n"
		"	-r --random-multimount-selection\n"
		"			use random replicated server selection\n"
		"	-m --dumpmaps [<map type> <map name>]\n"
		"			dump automounter maps and exit\n"
		"	-n --negative-timeout n\n"
		"			set the timeout for failed key lookups.\n"
		"	-P --positive-timeout n\n"
		"			set the positive timeout for key lookups.\n"
		"	-O --global-options\n"
		"			specify global mount options\n"
		"	-l --set-log-priority priority path [path,...]\n"
		"			set daemon log verbosity\n"
		"	-C --dont-check-daemon\n"
		"			don't check if daemon is already running\n"
		"	-F --force	forceably clean up known automounts at start\n"
		"	-U --force-exit	forceably clean up known automounts and exit\n"
		"	-V --version	print version, build config and exit\n"
		, program);
}

static void show_build_info(void)
{
	int count = 0;

	printf("\nLinux automount version %s\n", version);

	printf("\nDirectories:\n");
	printf("\tconfig dir:\t%s\n", confdir);
	printf("\tmaps dir:\t%s\n", mapdir);
	printf("\tmodules dir:\t%s\n", libdir);

	printf("\nCompile options:\n  ");

#ifndef ENABLE_MOUNT_LOCKING
	printf("DISABLE_MOUNT_LOCKING ");
	count = 22;
#endif

#ifdef ENABLE_FORCED_SHUTDOWN
	printf("ENABLE_FORCED_SHUTDOWN ");
	count = count + 23;
#endif

#ifdef ENABLE_IGNORE_BUSY_MOUNTS
	printf("ENABLE_IGNORE_BUSY_MOUNTS ");
	count = count + 26;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef WITH_SYSTEMD
	printf("WITH_SYSTEMD ");
	count = count + 13;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef WITH_HESIOD
	printf("WITH_HESIOD ");
	count = count + 12;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef WITH_LDAP
	printf("WITH_LDAP ");
	count = count + 10;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef WITH_SASL
	printf("WITH_SASL ");
	count = count + 10;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef WITH_DMALLOC
	printf("WITH_DMALLOC ");
	count = count + 13;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef LIBXML2_WORKAROUND
	printf("LIBXML2_WORKAROUND ");
	count = count + 19;

	if (count > 60) {
		printf("\n  ");
		count = 0;
	}
#endif

#ifdef WITH_LIBTIRPC
	printf("WITH_LIBTIRPC ");
	count = count + 14;
#endif

	printf("\n\n");

	return;
}

typedef struct _code {
	char	*c_name;
	int	c_val;
} CODE;

CODE prioritynames[] = {
	{ "alert",	LOG_ALERT },
	{ "crit",	LOG_CRIT },
	{ "debug",	LOG_DEBUG },
	{ "emerg",	LOG_EMERG },
	{ "err",	LOG_ERR },
	{ "error",	LOG_ERR },		/* DEPRECATED */
	{ "info",	LOG_INFO },
	{ "notice",	LOG_NOTICE },
	{ "panic", 	LOG_EMERG },		/* DEPRECATED */
	{ "warn",	LOG_WARNING },		/* DEPRECATED */
	{ "warning",	LOG_WARNING },
	{ NULL,		-1 },
};

static int convert_log_priority(char *priority_name)
{
	CODE *priority_mapping;

	for (priority_mapping = prioritynames;
	     priority_mapping->c_name != NULL;
	     priority_mapping++) {

		if (!strcasecmp(priority_name, priority_mapping->c_name))
			return priority_mapping->c_val;
	}

	return -1;
}

static void remove_empty_args(char **argv, int *argc)
{
	int next_to_last = *argc - 1;
	int i, j;

	for (i = j = 1; i < *argc; i++) {
		if (*argv[i]) {
			j++;
			continue;
		}

		while (i < *argc && argv[i] && !*argv[i]) i++;

		if (i == *argc)
			break;

		if (i == next_to_last) {
			if (*argv[i])
				argv[j++] = argv[i];
			break;
		} else {
			argv[j++] = argv[i];
			argv[i--] = "";
		}
	}
	*argc = j;
}

static void do_master_list_reset(struct master *master)
{
	struct list_head *head, *p, *n;

	master_mutex_lock();

	head = &master->mounts;
	n = head->next;
	while (n != head) {
		struct master_mapent *entry;

		p = n;
		n = p->next;

		entry = list_entry(p, struct master_mapent, list);

		if (!list_empty(&entry->list))
			list_del(&entry->list);
		master_free_mapent_sources(entry, 1);
		master_free_mapent(entry);
	}

	master_mutex_unlock();
}

static int do_master_read_master(struct master *master, time_t *age, int wait)
{
	sigset_t signalset, savesigset;
	/* Wait must be at least 1 second */
	unsigned int retry_wait = 2;
	unsigned int elapsed = 0;
	int max_wait = wait;
	int ret = 0;

	sigemptyset(&signalset);
	sigaddset(&signalset, SIGTERM);
	sigaddset(&signalset, SIGINT);
	sigaddset(&signalset, SIGHUP);
	pthread_sigmask(SIG_UNBLOCK, &signalset, &savesigset);

	while (1) {
		struct timespec t = { retry_wait, 0 };

		do_master_list_reset(master);

		*age = monotonic_time(NULL);
		if (master_read_master(master, *age)) {
			ret = 1;
			break;
		}

		if (nanosleep(&t, NULL) == -1)
			break;

		if (max_wait > 0) {
			elapsed += retry_wait;
			if (elapsed >= max_wait) {
				logmsg("problem reading master map, "
					"maximum wait exceeded");
				break;
			}
		}
	}

	pthread_sigmask(SIG_SETMASK, &savesigset, NULL);

	return ret;
}

int main(int argc, char *argv[])
{
	int res, opt, status;
	int logpri = -1;
	unsigned int flags;
	unsigned int logging;
	int debug_level = 0;
	unsigned master_read;
	int master_wait;
	time_t timeout;
	time_t age = monotonic_time(NULL);
	struct rlimit rlim;
	unsigned long max_open_files;
	const char *options = "+hp:t:vmd::D:SfVrO:l:n:P:CFUM:";
	static const struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"pid-file", 1, 0, 'p'},
		{"timeout", 1, 0, 't'},
		{"verbose", 0, 0, 'v'},
		{"debug", 2, 0, 'd'},
		{"define", 1, 0, 'D'},
		{"systemd-service", 0, 0, 'S'},
		{"foreground", 0, 0, 'f'},
		{"random-multimount-selection", 0, 0, 'r'},
		{"negative-timeout", 1, 0, 'n'},
		{"positive-timeout", 1, 0, 'P'},
		{"dumpmaps", 0, 0, 'm'},
		{"global-options", 1, 0, 'O'},
		{"version", 0, 0, 'V'},
		{"set-log-priority", 1, 0, 'l'},
		{"dont-check-daemon", 0, 0, 'C'},
		{"force", 0, 0, 'F'},
		{"force-exit", 0, 0, 'U'},
		{"master-wait", 1, 0, 'M'},
		{0, 0, 0, 0}
	};

	sigfillset(&block_sigs);
	/* allow for the dropping of core files */
	sigdelset(&block_sigs, SIGABRT);
	sigdelset(&block_sigs, SIGBUS);
	sigdelset(&block_sigs, SIGSEGV);
	sigdelset(&block_sigs, SIGILL);
	sigdelset(&block_sigs, SIGFPE);
	sigdelset(&block_sigs, SIGTRAP);
	pthread_sigmask(SIG_BLOCK, &block_sigs, NULL);

	program = argv[0];

	if (!defaults_read_config(0)) {
		printf("%s: failed to read configuration, exiting",
			program);
		exit(1);
	}

	nfs_mount_uses_string_options = check_nfs_mount_version(&vers, &check);

	flags = defaults_get_browse_mode() ? DAEMON_FLAGS_GHOST : 0;
	flags |= DAEMON_FLAGS_CHECK_DAEMON;

	kpkt_len = get_kpkt_len();
	master_wait = defaults_get_master_wait();
	timeout = defaults_get_timeout();
	logging = defaults_get_logging();
	global_selection_options = 0;
	global_options = NULL;

	remove_empty_args(argv, &argc);

	opterr = 0;
	while ((opt = getopt_long(argc, argv, options, long_options, NULL)) != EOF) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);

		case 'p':
			pid_file = optarg;
			break;

		case 't':
			timeout = getnumopt(optarg, opt);
			break;

		case 'v':
			logging |= LOGOPT_VERBOSE;
			break;

		case 'd':
			logging |= LOGOPT_DEBUG;
			if (optarg)
				debug_level = getsnumopt(optarg, opt);
			break;

		case 'D':
			macro_parse_globalvar(optarg);
			break;

		case 'S':
			flags |= DAEMON_FLAGS_SYSTEMD_SERVICE;
			break;

		case 'f':
			flags |= DAEMON_FLAGS_FOREGROUND;
			break;

		case 'V':
			show_build_info();
			exit(0);

		case 'r':
			global_selection_options |= MOUNT_FLAG_RANDOM_SELECT;
			break;

		case 'n':
			global_negative_timeout = getnumopt(optarg, opt);
			break;

		case 'P':
			global_positive_timeout = getnumopt(optarg, opt);
			break;

		case 'm':
			flags |= DAEMON_FLAGS_DUMP_MAPS;
			break;

		case 'M':
			master_wait = getnumopt(optarg, opt);
			break;

		case 'O':
			if (!(flags & DAEMON_FLAGS_HAVE_GLOBAL_OPTIONS)) {
				global_options = strdup(optarg);
				flags |= DAEMON_FLAGS_HAVE_GLOBAL_OPTIONS;
				break;
			}
			printf("%s: global options already specified.\n",
				program);
			break;

		case 'l':
			if (isalpha(*optarg)) {
				logpri = convert_log_priority(optarg);
				if (logpri < 0) {
					fprintf(stderr, "Invalid log priority:"
						" %s\n", optarg);
					exit(1);
				}
			} else if (isdigit(*optarg)) {
				logpri = getnumopt(optarg, opt);
			} else {
				fprintf(stderr, "non-alphanumeric character "
					"found in log priority.  Aborting.\n");
				exit(1);
			}
			break;

		case 'C':
			flags &= ~DAEMON_FLAGS_CHECK_DAEMON;
			break;

		case 'F':
			do_force_unlink = UNLINK_AND_CONT;
			break;

		case 'U':
			flags |= DAEMON_FLAGS_FOREGROUND;
			do_force_unlink = UNLINK_AND_EXIT;
			break;

		case '?':
		case ':':
			fprintf(stderr, "%s: Ambiguous or unknown options\n", program);
			fprintf(stderr, "Try `%s --help` for more information\n", program);
			exit(1);
		}
	}

	if (logging & LOGOPT_VERBOSE)
		set_log_verbose();

	if (logging & LOGOPT_DEBUG)
		set_log_debug(debug_level);

	if (geteuid() != 0) {
		fprintf(stderr, "%s: this program must be run by root.\n",
			program);
		exit(1);
	}

	/* Remove the options */
	argv += optind;
	argc -= optind;

	if (logpri >= 0) {
		int exit_code = 0;
		int i;

		/*
		 * The remaining argv elements are the paths for which
		 * log priorities must be changed.
		 */
		for (i = 0; i < argc; i++) {
			if (set_log_priority(argv[i], logpri) < 0)
				exit_code = 1;
		}
		if (argc < 1) {
			fprintf(stderr,
				"--set-log-priority requires a path.\n");
			exit_code = 1;
		}
		exit(exit_code);
	}

	/* Don't need the kernel module just to look at the configured maps */
	if (!(flags & DAEMON_FLAGS_DUMP_MAPS) &&
	   (!query_kproto_ver() || get_kver_major() < 5)) {
		fprintf(stderr,
			"%s: test mount forbidden or "
			"incorrect kernel protocol version, "
			"kernel protocol version 5.00 or above required.\n",
			program);
		exit(1);
	}

	max_open_files = defaults_get_open_file_limit();

	res = getrlimit(RLIMIT_NOFILE, &rlim);
	if (res == -1 || rlim.rlim_cur <= max_open_files)  {
		rlim.rlim_cur = max_open_files;
		if (rlim.rlim_max < max_open_files)
			rlim.rlim_max = max_open_files;
	}
	res = setrlimit(RLIMIT_NOFILE, &rlim);
	if (res)
		printf("%s: can't increase open file limit - continuing",
			program);

#if ENABLE_CORES
	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	res = setrlimit(RLIMIT_CORE, &rlim);
	if (res)
		printf("%s: can't increase core file limit - continuing",
			program);
#endif

	/* Get processor information for predefined escapes */
	macro_init();

	if (flags & DAEMON_FLAGS_DUMP_MAPS) {
		struct master_mapent *entry;
		struct list_head *head, *p;
		struct mapent_cache *nc;
		const char *type = NULL;
		const char *name = NULL;
		const char *master = NULL;

		if (argc > 0) {
			if (argc >= 2) {
				type = argv[0];
				name = argv[1];
			}
			if (argc == 3)
				master = argv[2];
		}

		status = pthread_key_create(&key_thread_stdenv_vars,
					key_thread_stdenv_vars_destroy);
		if (status) {
			logerr("%s: failed to create thread data key for std env vars!",
			       program);
			macro_free_global_table();
			exit(1);
		}

		status = pthread_key_create(&key_thread_attempt_id, free);
		if (status) {
			logerr("%s: failed to create thread data key for attempt ID!",
			       program);
			macro_free_global_table();
			exit(1);
		}

		if (master)
			master_list = master_new(NULL, timeout, flags);
		else
			master_list = master_new(master, timeout, flags);
		if (!master_list) {
			printf("%s: can't create master map", program);
			macro_free_global_table();
			exit(1);
		}

		log_to_stderr();

		master_init_scan();

		nc = cache_init_null_cache(master_list);
		if (!nc) {
			printf("%s: failed to init null map cache for %s",
				program, master_list->name);
			macro_free_global_table();
			exit(1);
		}
		master_list->nc = nc;

		lookup_nss_read_master(master_list, 0);
		if (type) {
			const char *map = basename(name);
			if (!map)
				printf("%s: invalid map name %s\n",
					program, name);
			else
				dump_map(master_list, type, map);
		} else
			master_show_mounts(master_list);

		head = &master_list->mounts;
		p = head->next;
		while (p != head) {
			entry = list_entry(p, struct master_mapent, list);
			p = p->next;
			master_free_mapent_sources(entry, 1);
			master_free_mapent(entry);
		}
		master_kill(master_list);
		macro_free_global_table();

		exit(0);
	}

	if (argc == 0)
		master_list = master_new(NULL, timeout, flags);
	else
		master_list = master_new(argv[0], timeout, flags);

	if (!master_list) {
		printf("%s: can't create master map %s", program, argv[0]);
		macro_free_global_table();
		exit(1);
	}

	become_daemon(flags);

	if (pthread_attr_init(&th_attr)) {
		logerr("%s: failed to init thread attribute struct!",
		     program);
		if (start_pipefd[1] != -1) {
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
		}
		release_flag_file();
		macro_free_global_table();
		exit(1);
	}

	if (pthread_attr_init(&th_attr_detached)) {
		logerr("%s: failed to init thread attribute struct!",
		     program);
		if (start_pipefd[1] != -1) {
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
		}
		release_flag_file();
		macro_free_global_table();
		exit(1);
	}

	if (pthread_attr_setdetachstate(
			&th_attr_detached, PTHREAD_CREATE_DETACHED)) {
		logerr("%s: failed to set detached thread attribute!",
		     program);
		if (start_pipefd[1] != -1) {
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
		}
		release_flag_file();
		macro_free_global_table();
		exit(1);
	}

	info(logging, "Starting automounter version %s, master map %s",
		version, master_list->name);
	info(logging, "using kernel protocol version %d.%02d",
		get_kver_major(), get_kver_minor());

	status = pthread_key_create(&key_thread_stdenv_vars,
				key_thread_stdenv_vars_destroy);
	if (status) {
		logerr("%s: failed to create thread data key for std env vars!",
		       program);
		master_kill(master_list);
		if (start_pipefd[1] != -1) {
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
		}
		release_flag_file();
		macro_free_global_table();
		exit(1);
	}

	status = pthread_key_create(&key_thread_attempt_id, free);
	if (status) {
		logerr("%s: failed to create thread data key for attempt ID!",
		       program);
		master_kill(master_list);
		if (start_pipefd[1] != -1) {
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
		}
		release_flag_file();
		macro_free_global_table();
		exit(1);
	}

	init_ioctl_ctl();

	if (!start_cmd_pipe_handler()) {
		logerr("%s: failed to create command pipe handler thread!", program);
		master_kill(master_list);
		if (start_pipefd[1] != -1) {
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
		}
		release_flag_file();
		macro_free_global_table();
		exit(1);
	}

	if (!alarm_start_handler()) {
		logerr("%s: failed to create alarm handler thread!", program);
		master_kill(master_list);
		if (start_pipefd[1] != -1) {
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
		}
		release_flag_file();
		macro_free_global_table();
		exit(1);
	}

	if (!st_start_handler()) {
		logerr("%s: failed to create FSM handler thread!", program);
		master_kill(master_list);
		if (start_pipefd[1] != -1) {
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
		}
		release_flag_file();
		macro_free_global_table();
		exit(1);
	}

#if defined(WITH_LDAP) && defined(LIBXML2_WORKAROUND)
	void *dh_xml2 = dlopen("libxml2.so", RTLD_NOW);
	if (!dh_xml2)
		dh_xml2 = dlopen("libxml2.so.2", RTLD_NOW);
	if (dh_xml2)
		xmlInitParser();
#endif
#ifdef TIRPC_WORKAROUND
	void *dh_tirpc = dlopen("libtirpc.so", RTLD_NOW);
	if (!dh_tirpc)
		dh_tirpc = dlopen("libtirpc.so.1", RTLD_NOW);
	if (!dh_tirpc)
		dh_tirpc = dlopen("libtirpc.so.3", RTLD_NOW);
#endif

	master_read = master_read_master(master_list, age);
	if (!master_read) {
		/*
		 * Read master map, waiting until it is available, unless
		 * a signal is received, in which case exit returning an
		 * error.
		 */
		if (!do_master_read_master(master_list, &age, master_wait)) {
			logmsg("%s: warning: could not read at least one "
				"map source after waiting, continuing ...",
				 program);
			/*
			 * Failed to read master map, continue with what
			 * we have anyway.
			 */
			master_mutex_lock();
			master_list->readall = 1;
			master_mount_mounts(master_list, age);
			master_list->readall = 0;

			if (list_empty(&master_list->mounts))
				warn(master_list->logopt, "no mounts in table");
			master_mutex_unlock();
		}
	}

	if (!(do_force_unlink & UNLINK_AND_EXIT)) {
		/*
		 * Mmm ... reset force unlink umount so we don't also do
		 * this in future when we receive a HUP signal.
		 */
		do_force_unlink = 0;

		if (start_pipefd[1] != -1) {
			st_stat = 0;
			res = write(start_pipefd[1], pst_stat, sizeof(*pst_stat));
			close(start_pipefd[1]);
		}

#ifdef WITH_SYSTEMD
		if (flags & DAEMON_FLAGS_SYSTEMD_SERVICE)
			sd_notify(1, "READY=1");
#endif

		signal_handler_thid = pthread_self();
		signal_handler(NULL);
	}

	master_kill(master_list);

	finish_cmd_pipe_handler();

	if (pid_file) {
		unlink(pid_file);
		pid_file = NULL;
	}
	defaults_conf_release();
	closelog();
	release_flag_file();
	macro_free_global_table();

#ifdef TIRPC_WORKAROUND
	if (dh_tirpc)
		dlclose(dh_tirpc);
#endif
#if defined(WITH_LDAP) && defined( LIBXML2_WORKAROUND)
	if (dh_xml2) {
		xmlCleanupParser();
		dlclose(dh_xml2);
	}
#endif
	close_ioctl_ctl();

	info(logging, "autofs stopped");

	exit(0);
}
