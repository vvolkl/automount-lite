/* ----------------------------------------------------------------------- *
 *   
 *  mounts.c - module for mount utilities.
 *
 *   Copyright 2002-2005 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <ctype.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <pwd.h>
#include <grp.h>
#include <libgen.h>

#include "automount.h"
#include "hashtable.h"

#define MAX_OPTIONS_LEN		80
#define MAX_MNT_NAME_LEN	30
#define MAX_ENV_NAME		15

#define EBUFSIZ 1024

const unsigned int t_indirect = AUTOFS_TYPE_INDIRECT;
const unsigned int t_direct = AUTOFS_TYPE_DIRECT;
const unsigned int t_offset = AUTOFS_TYPE_OFFSET;
const unsigned int type_count = 3;

static const char options_template[]       = "fd=%d,pgrp=%u,minproto=5,maxproto=%d";
static const char options_template_extra[] = "fd=%d,pgrp=%u,minproto=5,maxproto=%d,%s";
static const char mnt_name_template[]      = "automount(pid%u)";

static struct kernel_mod_version kver = {0, 0};
static const char kver_options_template[]  = "fd=%d,pgrp=%u,minproto=3,maxproto=5";

extern size_t detached_thread_stack_size;
static size_t maxgrpbuf = 0;

#define EXT_MOUNTS_HASH_BITS	6

struct ext_mount {
	unsigned int ref;
	char *mp;
	char *umount;
	struct hlist_node mount;
};
static DEFINE_HASHTABLE(ext_mounts_hash, EXT_MOUNTS_HASH_BITS);
static pthread_mutex_t ext_mount_hash_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MNTS_HASH_BITS	7

static DEFINE_HASHTABLE(mnts_hash, MNTS_HASH_BITS);
static pthread_mutex_t mnts_hash_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct tree_node *tree_mnt_new(void *ptr);
static int tree_mnt_cmp(struct tree_node *n, void *ptr);
static void tree_mnt_free(struct tree_node *n);

static struct tree_ops mnt_ops = {
	.new = tree_mnt_new,
	.cmp = tree_mnt_cmp,
	.free = tree_mnt_free,
};
static struct tree_ops *tree_mnt_ops = &mnt_ops;

static struct tree_node *tree_host_new(void *ptr);
static int tree_host_cmp(struct tree_node *n, void *ptr);
static void tree_host_free(struct tree_node *n);

static struct tree_ops host_ops = {
	.new = tree_host_new,
	.cmp = tree_host_cmp,
	.free = tree_host_free,
};
static struct tree_ops *tree_host_ops = &host_ops;

static struct tree_node *tree_mapent_new(void *ptr);
static int tree_mapent_cmp(struct tree_node *n, void *ptr);
static void tree_mapent_free(struct tree_node *n);

static struct tree_ops mapent_ops = {
	.new = tree_mapent_new,
	.cmp = tree_mapent_cmp,
	.free = tree_mapent_free,
};
static struct tree_ops *tree_mapent_ops = &mapent_ops;

unsigned int linux_version_code(void)
{
	struct utsname my_utsname;
	unsigned int p, q, r;
	char *tmp, *save;

	if (uname(&my_utsname))
		return 0;

	p = q = r = 0;

	tmp = strtok_r(my_utsname.release, ".", &save);
	if (!tmp)
		return 0;
	p = (unsigned int ) atoi(tmp);

	tmp = strtok_r(NULL, ".", &save);
	if (!tmp)
		return KERNEL_VERSION(p, 0, 0);
	q = (unsigned int) atoi(tmp);

	tmp = strtok_r(NULL, ".", &save);
	if (!tmp)
		return KERNEL_VERSION(p, q, 0);
	r = (unsigned int) atoi(tmp);

	return KERNEL_VERSION(p, q, r);
}

unsigned int query_kproto_ver(void)
{
	struct ioctl_ops *ops;
	char dir[] = "/tmp/autoXXXXXX", *t_dir;
	char options[MAX_OPTIONS_LEN + 1];
	pid_t pgrp = getpgrp();
	int pipefd[2], ioctlfd, len;
	struct stat st;

	t_dir = mkdtemp(dir);
	if (!t_dir)
		return 0;

	if (pipe(pipefd) == -1) {
		rmdir(t_dir);
		return 0;
	}

	len = snprintf(options, MAX_OPTIONS_LEN,
		       kver_options_template, pipefd[1], (unsigned) pgrp);
	if (len < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		rmdir(t_dir);
		return 0;
	}

	if (mount("automount", t_dir, "autofs", MS_MGC_VAL, options)) {
		close(pipefd[0]);
		close(pipefd[1]);
		rmdir(t_dir);
		return 0;
	}

	close(pipefd[1]);

	if (stat(t_dir, &st) == -1) {
		umount(t_dir);
		close(pipefd[0]);
		rmdir(t_dir);
		return 0;
	}

	ops = get_ioctl_ops();
	if (!ops) {
		umount(t_dir);
		close(pipefd[0]);
		rmdir(t_dir);
		return 0;
	}

	ops->open(LOGOPT_NONE, &ioctlfd, st.st_dev, t_dir);
	if (ioctlfd == -1) {
		umount(t_dir);
		close(pipefd[0]);
		close_ioctl_ctl();
		rmdir(t_dir);
		return 0;
	}

	ops->catatonic(LOGOPT_NONE, ioctlfd);

	/* If this ioctl() doesn't work, it is kernel version 2 */
	if (ops->protover(LOGOPT_NONE, ioctlfd, &kver.major)) {
		ops->close(LOGOPT_NONE, ioctlfd);
		umount(t_dir);
		close(pipefd[0]);
		close_ioctl_ctl();
		rmdir(t_dir);
		return 0;
	}

	/* If this ioctl() doesn't work, version is 4 or less */
	if (ops->protosubver(LOGOPT_NONE, ioctlfd, &kver.minor)) {
		ops->close(LOGOPT_NONE, ioctlfd);
		umount(t_dir);
		close(pipefd[0]);
		close_ioctl_ctl();
		rmdir(t_dir);
		return 0;
	}

	ops->close(LOGOPT_NONE, ioctlfd);
	umount(t_dir);
	close(pipefd[0]);
	close_ioctl_ctl();
	rmdir(t_dir);

	return 1;
}

unsigned int get_kver_major(void)
{
	return kver.major;
}

unsigned int get_kver_minor(void)
{
	return kver.minor;
}

int open_ioctlfd(struct autofs_point *ap, const char *path, dev_t dev)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	int fd = -1;
	int error;

	error = ops->open(ap->logopt, &fd, dev, path);
	if (error == -1) {
		char buf[MAX_ERR_BUF];
		int err = errno;
		char *estr;

		if (errno == ENOENT)
			return -1;

		estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      "failed to open ioctlfd for %s, error: %s",
		      path, estr);
		errno = err;
		return -1;
	}

	return fd;
}

#ifdef HAVE_MOUNT_NFS
static int extract_version(char *start, struct nfs_mount_vers *vers)
{
	char *s_ver = strchr(start, ' ');
	if (!s_ver)
		return 0;
	while (*s_ver && !isdigit(*s_ver)) {
		s_ver++;
		if (!*s_ver)
			return 0;
		break;
	}
	vers->major = atoi(strtok(s_ver, "."));
	vers->minor = (unsigned int) atoi(strtok(NULL, "."));
	vers->fix = (unsigned int) atoi(strtok(NULL, "."));
	return 1;
}

int check_nfs_mount_version(struct nfs_mount_vers *vers,
			    struct nfs_mount_vers *check)
{
	pid_t f;
	int ret, status, pipefd[2];
	char errbuf[EBUFSIZ + 1], *p, *sp;
	int errp, errn;
	sigset_t allsigs, tmpsig, oldsig;
	char *s_ver;
	int cancel_state;

	if (open_pipe(pipefd))
		return -1;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	sigfillset(&allsigs);
	pthread_sigmask(SIG_BLOCK, &allsigs, &oldsig);

	open_mutex_lock();
	f = fork();
	if (f == 0) {
		reset_signals();
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);

		execl(PATH_MOUNT_NFS, PATH_MOUNT_NFS, "-V", (char *) NULL);
		_exit(255);	/* execv() failed */
	}

	ret = 0;

	tmpsig = oldsig;

	sigaddset(&tmpsig, SIGCHLD);
	pthread_sigmask(SIG_SETMASK, &tmpsig, NULL);
	open_mutex_unlock();

	close(pipefd[1]);

	if (f < 0) {
		close(pipefd[0]);
		pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
		pthread_setcancelstate(cancel_state, NULL);
		return -1;
	}

	errp = 0;
	do {
		while (1) {
			errn = read(pipefd[0], errbuf + errp, EBUFSIZ - errp);
			if (errn == -1 && errno == EINTR)
				continue;
			break;
		}

		if (errn > 0) {
			errp += errn;

			sp = errbuf;
			while (errp && (p = memchr(sp, '\n', errp))) {
				*p++ = '\0';
				errp -= (p - sp);
				sp = p;
			}

			if (errp && sp != errbuf)
				memmove(errbuf, sp, errp);

			if (errp >= EBUFSIZ) {
				/* Line too long, split */
				errbuf[errp] = '\0';
				if ((s_ver = strstr(errbuf, "nfs-utils"))) {
					if (extract_version(s_ver, vers))
						ret = 1;
				}
				errp = 0;
			}

			if ((s_ver = strstr(errbuf, "nfs-utils"))) {
				if (extract_version(s_ver, vers))
					ret = 1;
			}
		}
	} while (errn > 0);

	close(pipefd[0]);

	if (errp > 0) {
		/* End of file without \n */
		errbuf[errp] = '\0';
		if ((s_ver = strstr(errbuf, "nfs-utils"))) {
			if (extract_version(s_ver, vers))
				ret = 1;
		}
	}

	if (ret) {
		if ((vers->major < check->major) ||
		    ((vers->major == check->major) && (vers->minor < check->minor)) ||
		    ((vers->major == check->major) && (vers->minor == check->minor) &&
		     (vers->fix < check->fix)))
			ret = 0;
	}

	if (waitpid(f, &status, 0) != f)
		debug(LOGOPT_NONE, "no process found to wait for");

	pthread_sigmask(SIG_SETMASK, &oldsig, NULL);
	pthread_setcancelstate(cancel_state, NULL);

	return ret;
}
#else
int check_nfs_mount_version(struct nfs_mount_vers *vers,
			    struct nfs_mount_vers *check)
{
	return 0;
}
#endif

int mount_fullpath(char *fullpath, size_t max_len,
		   const char *root, size_t root_len, const char *name)
{
	int last, len;

	if (root_len)
		last = root_len - 1;
	else
		last = strlen(root) - 1;

	/* Root offset of multi-mount or direct or offset mount.
	 * Direct or offset mount, name (or root) is absolute path.
	 */
	if (root[last] == '/')
		len = snprintf(fullpath, max_len, "%s", root);
	else if (*name == '/')
		len = snprintf(fullpath, max_len, "%s", name);
	else
		len = snprintf(fullpath, max_len, "%s/%s", root, name);

	if (len >= max_len)
		return 0;

	fullpath[len] = '\0';

	return len;
}

static char *set_env_name(const char *prefix, const char *name, char *buf)
{
	size_t len;

	len = strlen(name);
	if (prefix)
		len += strlen(prefix);
	len++;

	if (len > MAX_ENV_NAME)
		return NULL;

	if (!prefix)
		strcpy(buf, name);
	else {
		strcpy(buf, prefix);
		strcat(buf, name);
	}
	return buf;
}

static struct substvar *do_macro_addvar(struct substvar *list,
					const char *prefix,
					const char *name,
					const char *val)
{
	char buf[MAX_ENV_NAME + 1];
	char *new;
	size_t len;

	new = set_env_name(prefix, name, buf);
	if (new) {
		len = strlen(new);
		list = macro_addvar(list, new, len, val);
	}
	return list;
}

static struct substvar *do_macro_removevar(struct substvar *list,
					   const char *prefix,
					   const char *name)
{
	char buf[MAX_ENV_NAME + 1];
	char *new;
	size_t len;

	new = set_env_name(prefix, name, buf);
	if (new) {
		len = strlen(new);
		list = macro_removevar(list, new, len);
	}
	return list;
}

struct substvar *addstdenv(struct substvar *sv, const char *prefix)
{
	struct substvar *list = sv;
	struct thread_stdenv_vars *tsv;
	char numbuf[16];

	tsv = pthread_getspecific(key_thread_stdenv_vars);
	if (tsv) {
		const struct substvar *mv;
		int ret;
		long num;

		num = (long) tsv->uid;
		ret = sprintf(numbuf, "%ld", num);
		if (ret > 0)
			list = do_macro_addvar(list, prefix, "UID", numbuf);
		num = (long) tsv->gid;
		ret = sprintf(numbuf, "%ld", num);
		if (ret > 0)
			list = do_macro_addvar(list, prefix, "GID", numbuf);
		list = do_macro_addvar(list, prefix, "USER", tsv->user);
		list = do_macro_addvar(list, prefix, "GROUP", tsv->group);
		list = do_macro_addvar(list, prefix, "HOME", tsv->home);
		mv = macro_findvar(list, "HOST", 4);
		if (mv) {
			char *shost = strdup(mv->val);
			if (shost) {
				char *dot = strchr(shost, '.');
				if (dot)
					*dot = '\0';
				list = do_macro_addvar(list,
						       prefix, "SHOST", shost);
				free(shost);
			}
		}
	}
	return list;
}

struct substvar *removestdenv(struct substvar *sv, const char *prefix)
{
	struct substvar *list = sv;

	list = do_macro_removevar(list, prefix, "UID");
	list = do_macro_removevar(list, prefix, "USER");
	list = do_macro_removevar(list, prefix, "HOME");
	list = do_macro_removevar(list, prefix, "GID");
	list = do_macro_removevar(list, prefix, "GROUP");
	list = do_macro_removevar(list, prefix, "SHOST");
	return list;
}

void add_std_amd_vars(struct substvar *sv)
{
	char *tmp;

	tmp = conf_amd_get_arch();
	if (tmp) {
		macro_global_addvar("arch", 4, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_karch();
	if (tmp) {
		macro_global_addvar("karch", 5, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_os();
	if (tmp) {
		macro_global_addvar("os", 2, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_full_os();
	if (tmp) {
		macro_global_addvar("full_os", 7, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_os_ver();
	if (tmp) {
		macro_global_addvar("osver", 5, tmp);
		free(tmp);
	}

	tmp = conf_amd_get_vendor();
	if (tmp) {
		macro_global_addvar("vendor", 6, tmp);
		free(tmp);
	}

	/* Umm ... HP_UX cluster name, probably not used */
	tmp = conf_amd_get_cluster();
	if (tmp) {
		macro_global_addvar("cluster", 7, tmp);
		free(tmp);
	} else {
		const struct substvar *v = macro_findvar(sv, "domain", 4);
		if (v && *v->val) {
			tmp = strdup(v->val);
			if (tmp) {
				macro_global_addvar("cluster", 7, tmp);
				free(tmp);
			}
		}
	}

	tmp = conf_amd_get_auto_dir();
	if (tmp) {
		macro_global_addvar("autodir", 7, tmp);
		free(tmp);
	}

	return;
}

void remove_std_amd_vars(void)
{
	macro_global_removevar("autodir", 7);
	macro_global_removevar("cluster", 7);
	macro_global_removevar("vendor", 6);
	macro_global_removevar("osver", 5);
	macro_global_removevar("full_os", 7);
	macro_global_removevar("os", 2);
	macro_global_removevar("karch", 5);
	macro_global_removevar("arch", 4);
	return;
 }

struct amd_entry *new_amd_entry(const struct substvar *sv)
{
	struct amd_entry *new;
	const struct substvar *v;
	char *path;

	v = macro_findvar(sv, "path", 4);
	if (!v)
		return NULL;

	path = strdup(v->val);
	if (!path)
		return NULL;

	new = malloc(sizeof(struct amd_entry));
	if (!new) {
		free(path);
		return NULL;
	}

	memset(new, 0, sizeof(*new));
	new->path = path;
	INIT_LIST_HEAD(&new->list);

	return new;
}

void clear_amd_entry(struct amd_entry *entry)
{
	if (!entry)
		return;
	if (entry->path)
		free(entry->path);
	if (entry->map_type)
		free(entry->map_type);
	if (entry->pref)
		free(entry->pref);
	if (entry->fs)
		free(entry->fs);
	if (entry->rhost)
		free(entry->rhost);
	if (entry->rfs)
		free(entry->rfs);
	if (entry->opts)
		free(entry->opts);
	if (entry->addopts)
		free(entry->addopts);
	if (entry->remopts)
		free(entry->remopts);
	if (entry->sublink)
		free(entry->sublink);
	if (entry->selector)
		free_selector(entry->selector);
	return;
}

void free_amd_entry(struct amd_entry *entry)
{
	clear_amd_entry(entry);
	free(entry);
	return;
}

void free_amd_entry_list(struct list_head *entries)
{
	if (!list_empty(entries)) {
		struct list_head *head = entries;
		struct amd_entry *this;
		struct list_head *p;

		p = head->next;
		while (p != head) {
			this = list_entry(p, struct amd_entry, list);
			p = p->next;
			free_amd_entry(this);
		}
	}
}

static int cacl_max_options_len(unsigned int flags)
{
	unsigned int kver_major = get_kver_major();
	unsigned int kver_minor = get_kver_minor();
	int max_len;

	/* %d and %u are maximum lenght of 10 and mount type is maximum
	 * length of 9 (e. ",indirect").
	 * The base temaplate is "fd=%d,pgrp=%u,minproto=5,maxproto=%d"
	 * plus the length of mount type plus 1 for the NULL.
	 */
	max_len = 79 + 1;

	if (kver_major < 5 || (kver_major == 5 && kver_minor < 4))
		goto out;

	/* maybe add ",strictexpire" */
	if (flags & MOUNT_FLAG_STRICTEXPIRE)
		max_len += 13;

	if (kver_major == 5 && kver_minor < 5)
		goto out;

	/* maybe add ",ignore" */
	if (flags & MOUNT_FLAG_IGNORE)
		max_len += 7;
out:
	return max_len;
}

/*
 * Make common autofs mount options string
 */
char *make_options_string(char *path, int pipefd,
			  const char *type, unsigned int flags)
{
	unsigned int kver_major = get_kver_major();
	unsigned int kver_minor = get_kver_minor();
	char *options;
	int max_len, len, new;

	max_len = cacl_max_options_len(flags);

	options = malloc(max_len);
	if (!options) {
		logerr("can't malloc options string");
		return NULL;
	}

	if (type)
		len = snprintf(options, max_len,
				options_template_extra,
				pipefd, (unsigned) getpgrp(),
				AUTOFS_MAX_PROTO_VERSION, type);
	else
		len = snprintf(options, max_len, options_template,
			pipefd, (unsigned) getpgrp(),
			AUTOFS_MAX_PROTO_VERSION);

	if (len < 0)
		goto error_out;

	if (len >= max_len)
		goto truncated;

	if (kver_major < 5 || (kver_major == 5 && kver_minor < 4))
		goto out;

	/* maybe add ",strictexpire" */
	if (flags & MOUNT_FLAG_STRICTEXPIRE) {
		new = snprintf(options + len,
			       max_len, "%s", ",strictexpire");
		if (new < 0)
		       goto error_out;
		len += new;
		if (len >= max_len)
			goto truncated;
	}

	if (kver_major == 5 && kver_minor < 5)
		goto out;

	/* maybe add ",ignore" */
	if (flags & MOUNT_FLAG_IGNORE) {
		new = snprintf(options + len,
			       max_len, "%s", ",ignore");
		if (new < 0)
		       goto error_out;
		len += new;
		if (len >= max_len)
			goto truncated;
	}
out:
	options[len] = '\0';
	return options;

truncated:
	logerr("buffer to small for options - truncated");
	len = max_len -1;
	goto out;

error_out:
	logerr("error constructing mount options string for %s", path);
	free(options);
	return NULL;
}

char *make_mnt_name_string(char *path)
{
	char *mnt_name;
	int len;

	mnt_name = malloc(MAX_MNT_NAME_LEN + 1);
	if (!mnt_name) {
		logerr("can't malloc mnt_name string");
		return NULL;
	}

	len = snprintf(mnt_name, MAX_MNT_NAME_LEN,
			mnt_name_template, (unsigned) getpid());

	if (len >= MAX_MNT_NAME_LEN) {
		logerr("buffer to small for mnt_name - truncated");
		len = MAX_MNT_NAME_LEN - 1;
	}

	if (len < 0) {
		logerr("failed setting up mnt_name for autofs path %s", path);
		free(mnt_name);
		return NULL;
	}
	mnt_name[len] = '\0';

	return mnt_name;
}

static void ext_mount_hash_mutex_lock(void)
{
	int status = pthread_mutex_lock(&ext_mount_hash_mutex);
	if (status)
		fatal(status);
}

static void ext_mount_hash_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&ext_mount_hash_mutex);
	if (status)
		fatal(status);
}

static struct ext_mount *ext_mount_lookup(const char *mp)
{
	uint32_t hval = hash(mp, HASH_SIZE(ext_mounts_hash));
	struct ext_mount *this;

	hlist_for_each_entry(this, &ext_mounts_hash[hval], mount) {
		if (!strcmp(this->mp, mp))
			return this;
	}

	return NULL;
}

int ext_mount_add(const char *path, const char *umount)
{
	struct ext_mount *em;
	int ret = 0;

	ext_mount_hash_mutex_lock();

	em = ext_mount_lookup(path);
	if (em) {
		em->ref++;
		ret = 1;
		goto done;
	}

	em = malloc(sizeof(struct ext_mount));
	if (!em)
		goto done;
	memset(em, 0, sizeof(*em));

	em->mp = strdup(path);
	if (!em->mp) {
		free(em);
		goto done;
	}
	if (umount) {
		em->umount = strdup(umount);
		if (!em->umount) {
			free(em->mp);
			free(em);
			goto done;
		}
	}
	em->ref = 1;
	INIT_HLIST_NODE(&em->mount);

	hash_add_str(ext_mounts_hash, &em->mount, em->mp);

	ret = 1;
done:
	ext_mount_hash_mutex_unlock();
	return ret;
}

int ext_mount_remove(const char *path)
{
	struct ext_mount *em;
	int ret = 0;

	ext_mount_hash_mutex_lock();

	em = ext_mount_lookup(path);
	if (!em)
		goto done;

	em->ref--;
	if (em->ref)
		goto done;
	else {
		hlist_del_init(&em->mount);
		free(em->mp);
		if (em->umount)
			free(em->umount);
		free(em);
		ret = 1;
	}
done:
	ext_mount_hash_mutex_unlock();
	return ret;
}

int ext_mount_inuse(const char *path)
{
	struct ext_mount *em;
	int ret = 0;

	ext_mount_hash_mutex_lock();
	em = ext_mount_lookup(path);
	if (!em)
		goto done;
	ret = em->ref;
done:
	ext_mount_hash_mutex_unlock();
	return ret;
}

static void mnts_hash_mutex_lock(void)
{
	int status = pthread_mutex_lock(&mnts_hash_mutex);
	if (status)
		fatal(status);
}

static void mnts_hash_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&mnts_hash_mutex);
	if (status)
		fatal(status);
}

static struct mnt_list *mnts_lookup(const char *mp)
{
	uint32_t hval = hash(mp, HASH_SIZE(mnts_hash));
	struct mnt_list *this;

	if (hlist_empty(&mnts_hash[hval]))
		return NULL;

	hlist_for_each_entry(this, &mnts_hash[hval], hash) {
		if (!strcmp(this->mp, mp) && this->ref)
			return this;
	}

	return NULL;
}

static struct mnt_list *mnts_alloc_mount(const char *mp)
{
	struct mnt_list *this;

	this = malloc(sizeof(*this));
	if (!this)
		goto done;
	memset(this, 0, sizeof(*this));

	this->mp = strdup(mp);
	if (!this->mp) {
		free(this);
		this = NULL;
		goto done;
	}
	this->len = strlen(mp);

	this->ref = 1;
	INIT_HLIST_NODE(&this->hash);
	INIT_LIST_HEAD(&this->mount);
	INIT_LIST_HEAD(&this->submount);
	INIT_LIST_HEAD(&this->submount_work);
	INIT_LIST_HEAD(&this->amdmount);
	INIT_LIST_HEAD(&this->expire);
	INIT_TREE_NODE(&this->node);
done:
	return this;
}

static void __mnts_get_mount(struct mnt_list *mnt)
{
	mnt->ref++;
}

static void __mnts_put_mount(struct mnt_list *mnt)
{
	mnt->ref--;
	if (!mnt->ref) {
		hash_del(&mnt->hash);
		free(mnt->mp);
		free(mnt);
	}
}

static struct mnt_list *mnts_new_mount(const char *mp)
{
	struct mnt_list *this;

	this = mnts_lookup(mp);
	if (this) {
		__mnts_get_mount(this);
		goto done;
	}

	this = mnts_alloc_mount(mp);
	if (!this)
		goto done;

	hash_add_str(mnts_hash, &this->hash, this->mp);
done:
	return this;
}

static struct mnt_list *mnts_get_mount(const char *mp)
{
	struct mnt_list *this;

	this = mnts_lookup(mp);
	if (this) {
		__mnts_get_mount(this);
		return this;
	}

	return mnts_new_mount(mp);
}

static struct mnt_list *__mnts_lookup_mount(const char *mp)
{
	struct mnt_list *this;

	this = mnts_lookup(mp);
	if (this)
		__mnts_get_mount(this);

	return this;
}

struct mnt_list *mnts_lookup_mount(const char *mp)
{
	struct mnt_list *this;

	mnts_hash_mutex_lock();
	this = __mnts_lookup_mount(mp);
	mnts_hash_mutex_unlock();

	return this;
}

void mnts_put_mount(struct mnt_list *mnt)
{
	if (!mnt)
		return;
	mnts_hash_mutex_lock();
	__mnts_put_mount(mnt);
	mnts_hash_mutex_unlock();
}

struct mnt_list *mnts_find_submount(const char *path)
{
	struct mnt_list *mnt;

	mnt = mnts_lookup_mount(path);
	if (mnt && mnt->flags & MNTS_AUTOFS)
		return mnt;
	mnts_put_mount(mnt);
	return NULL;
}

static struct autofs_point *__mnt_find_submount_by_devid(struct list_head *submounts, dev_t devid)
{
	struct autofs_point *ap = NULL;
	struct list_head *p;

	list_for_each(p, submounts) {
		struct mnt_list *this;

		this = list_entry(p, struct mnt_list, submount);

		if (this->ap->dev == devid) {
			ap = this->ap;
			break;
		}

		ap = mnt_find_submount_by_devid(&this->ap->submounts, devid);
		if (ap)
			break;
	}

	return ap;
}

struct autofs_point *mnt_find_submount_by_devid(struct list_head *submounts, dev_t devid)
{
	struct autofs_point *ap = NULL;

	mnts_hash_mutex_lock();
	ap = __mnt_find_submount_by_devid(submounts, devid);
	mnts_hash_mutex_unlock();

	return ap;
}

struct mnt_list *mnts_add_submount(struct autofs_point *ap)
{
	struct mnt_list *this;

	mnts_hash_mutex_lock();
	this = mnts_get_mount(ap->path);
	if (this) {
		if (!this->ap)
			this->ap = ap;
		else if (this->ap != ap ||
			 this->ap->parent != ap->parent) {
			__mnts_put_mount(this);
			mnts_hash_mutex_unlock();
			error(ap->logopt,
			      "conflict with submount owner: %s", ap->path);
			goto fail;
		}
		this->flags |= MNTS_AUTOFS;
		if (list_empty(&this->submount))
			list_add_tail(&this->submount, &ap->parent->submounts);
	}
	mnts_hash_mutex_unlock();
fail:
	return this;
}

void mnts_remove_submount(const char *mp)
{
	struct mnt_list *this;

	mnts_hash_mutex_lock();
	this = mnts_lookup(mp);
	if (this && this->flags & MNTS_AUTOFS) {
		this->flags &= ~MNTS_AUTOFS;
		this->ap = NULL;
		list_del_init(&this->submount);
		__mnts_put_mount(this);
	}
	mnts_hash_mutex_unlock();
}

struct mnt_list *mnts_find_amdmount(const char *path)
{
	struct mnt_list *mnt;

	mnt = mnts_lookup_mount(path);
	if (mnt && mnt->flags & MNTS_AMD_MOUNT)
		return mnt;
	mnts_put_mount(mnt);
	return NULL;
}

struct mnt_list *mnts_add_amdmount(struct autofs_point *ap, struct amd_entry *entry)
{
	struct mnt_list *this;
	char *type, *ext_mp, *pref, *opts;

	ext_mp = pref = type = opts = NULL;

	if (entry->fs) {
		ext_mp = strdup(entry->fs);
		if (!ext_mp)
			goto fail;
	}

	if (entry->pref) {
		pref = strdup(entry->pref);
		if (!pref)
			goto fail;
	}

	if (entry->type) {
		type = strdup(entry->type);
		if (!type)
			goto fail;
	}

	if (entry->opts) {
		opts = strdup(entry->opts);
		if (!opts)
			goto fail;
	}

	mnts_hash_mutex_lock();
	this = mnts_get_mount(entry->path);
	if (!this)
		goto fail;
	this->ext_mp = ext_mp;
	this->amd_pref = pref;
	this->amd_type = type;
	this->amd_opts = opts;
	this->amd_cache_opts = entry->cache_opts;
	this->flags |= MNTS_AMD_MOUNT;
	if (list_empty(&this->amdmount))
		list_add_tail(&this->amdmount, &ap->amdmounts);
	mnts_hash_mutex_unlock();

	return this;
fail:
	if (ext_mp)
		free(ext_mp);
	if (pref)
		free(pref);
	if (type)
		free(type);
	if (opts)
		free(opts);
	return NULL;
}

static void __mnts_remove_amdmount(const char *mp)
{
	struct mnt_list *this;

	this = mnts_lookup(mp);
	if (!(this && this->flags & MNTS_AMD_MOUNT))
		return;
	this->flags &= ~MNTS_AMD_MOUNT;
	list_del_init(&this->amdmount);
	if (this->ext_mp) {
		free(this->ext_mp);
		this->ext_mp = NULL;
	}
	if (this->amd_type) {
		free(this->amd_type);
		this->amd_type = NULL;
	}
	if (this->amd_pref) {
		free(this->amd_pref);
		this->amd_pref = NULL;
	}
	if (this->amd_opts) {
		free(this->amd_opts);
		this->amd_opts = NULL;
	}
	this->amd_cache_opts = 0;
	__mnts_put_mount(this);
}

void mnts_remove_amdmount(const char *mp)
{
	mnts_hash_mutex_lock();
	__mnts_remove_amdmount(mp);
	mnts_hash_mutex_unlock();
}

void mnts_remove_amdmounts(struct autofs_point *ap)
{
	struct list_head *head, *p;

	mnts_hash_mutex_lock();
	head = &ap->amdmounts;
	p = head->next;
	while (p != head) {
		struct mnt_list *mnt = list_entry(p, struct mnt_list, amdmount);
		p = p->next;
		ext_mount_remove(mnt->ext_mp);
		__mnts_remove_amdmount(mnt->mp);
	}
	mnts_hash_mutex_unlock();
}

struct mnt_list *mnts_add_mount(struct autofs_point *ap,
				const char *name, unsigned int flags)
{
	struct mnt_list *this;
	char *mp;

	if (*name == '/') {
		mp = strdup(name);
		if (!mp)
			return NULL;
	} else {
		int len = ap->len + strlen(name) + 2;

		mp = malloc(len);
		if (!mp)
			return NULL;
		strcpy(mp, ap->path);
		strcat(mp, "/");
		strcat(mp, name);
	}

	mnts_hash_mutex_lock();
	this = mnts_get_mount(mp);
	if (this) {
		this->flags |= flags;
		if ((this->flags & MNTS_MOUNTED) && list_empty(&this->mount))
			list_add(&this->mount, &ap->mounts);
	}
	mnts_hash_mutex_unlock();
	free(mp);

	return this;
}

void mnts_remove_mount(const char *mp, unsigned int flags)
{
	struct mnt_list *this;

	mnts_hash_mutex_lock();
	this = mnts_lookup(mp);
	if (this && this->flags & flags) {
		this->flags &= ~flags;
		if (!(this->flags & MNTS_MOUNTED))
			list_del_init(&this->mount);
		__mnts_put_mount(this);
	}
	mnts_hash_mutex_unlock();
}

void mnts_set_mounted_mount(struct autofs_point *ap, const char *name, unsigned int flags)
{
	struct mnt_list *mnt;

	mnt = mnts_add_mount(ap, name, flags);
	if (!mnt) {
		error(ap->logopt,
		      "failed to add mount %s to mounted list", name);
		return;
	}
}

unsigned int mnts_has_mounted_mounts(struct autofs_point *ap)
{
	unsigned int has_mounted_mounts = 0;

	mnts_hash_mutex_lock();
	if (list_empty(&ap->mounts))
		goto done;
	has_mounted_mounts = 1;
done:
	mnts_hash_mutex_unlock();
	return has_mounted_mounts;
}

static inline struct tree_node *tree_root(struct tree_ops *ops, void *ptr)
{
	return ops->new(ptr);
}

static struct tree_node *tree_add_left(struct tree_node *n, void *ptr)
{
	struct tree_node *new;

	new = n->ops->new(ptr);
	n->left = new;

	return new;
}

static struct tree_node *tree_add_right(struct tree_node *n, void *ptr)
{
	struct tree_node *new;

	new = n->ops->new(ptr);
	n->right = new;

	return new;
}

static struct tree_node *tree_add_node(struct tree_node *root, void *ptr)
{
	struct tree_node *p, *q;
	struct tree_ops *ops = root->ops;
	int eq;

	q = root;
	p = root;

	while (q) {
		p = q;
		eq = ops->cmp(p, ptr);
		if (!eq)
			break;
		if (eq < 0)
			q = p->left;
		else
			q = p->right;
	}

	if (!eq)
		return p;
	else {
		if (eq < 0)
			return tree_add_left(p, ptr);
		else
			return tree_add_right(p, ptr);
	}

	return NULL;
}

void tree_free(struct tree_node *root)
{
	struct tree_ops *ops = root->ops;

	if (root->right)
		tree_free(root->right);
	if (root->left)
		tree_free(root->left);
	ops->free(root);
}

int tree_traverse_inorder(struct tree_node *n, tree_work_fn_t work, void *ptr)
{
	int ret;

	if (n->left) {
		ret = tree_traverse_inorder(n->left, work, ptr);
		if (!ret)
			goto done;
	}
	ret = work(n, ptr);
	if (!ret)
		goto done;
	if (n->right) {
		ret = tree_traverse_inorder(n->right, work, ptr);
		if (!ret)
			goto done;
	}
done:
	return ret;
}

static struct tree_node *tree_mnt_root(struct mnt_list *mnt)
{
	return tree_root(tree_mnt_ops, mnt);
}

static struct tree_node *tree_mnt_new(void *ptr)
{
	struct tree_node *n = MNT_LIST_NODE(ptr);

	n->ops = tree_mnt_ops;
	n->left = NULL;
	n->right = NULL;

	return n;
}

static int tree_mnt_cmp(struct tree_node *n, void *ptr)
{
	struct mnt_list *n_mnt = MNT_LIST(n);
	size_t n_mnt_len = n_mnt->len;
	struct mnt_list *mnt = ptr;
	size_t mnt_len = mnt->len;
	int eq;

	eq = strcmp(mnt->mp, n_mnt->mp);
	if (!eq)
		return 0;
	return (mnt_len < n_mnt_len) ? -1 : 1;
}

static void tree_mnt_free(struct tree_node *n)
{
	n->ops = NULL;
	n->left = NULL;
	n->right = NULL;
}

static int tree_mnt_expire_list_work(struct tree_node *n, void *ptr)
{
	struct mnt_list *mnt = MNT_LIST(n);
	struct list_head *mnts = ptr;

	/* The expire of the root offset of an offset tree is the same
	 * as expiring the offset tree root itself (if theree is a root
	 * offset).
	 */
	if (mnt->mp[mnt->len - 1] != '/')
		list_add(&mnt->expire, mnts);

	return 1;
}

void mnts_get_expire_list(struct list_head *mnts, struct autofs_point *ap)
{
	struct tree_node *tree = NULL;
	struct mnt_list *mnt;

	mnts_hash_mutex_lock();
	if (list_empty(&ap->mounts))
		goto done;

	list_for_each_entry(mnt, &ap->mounts, mount) {
		struct tree_node *n;

		if (!(mnt->flags & MNTS_MOUNTED))
			continue;

		__mnts_get_mount(mnt);

		if (!tree) {
			tree = tree_mnt_root(mnt);
			if (!tree) {
				error(LOGOPT_ANY, "failed to create expire tree root");
				goto done;
			}
			continue;
		}

		n = tree_add_node(tree, mnt);
		if (!n) {
			error(LOGOPT_ANY, "failed to add expire tree node");
			tree_free(tree);
			goto done;
		}
	}

	if (tree) {
		tree_traverse_inorder(tree, tree_mnt_expire_list_work, mnts);
		tree_free(tree);
	}
done:
	mnts_hash_mutex_unlock();
}

void mnts_put_expire_list(struct list_head *mnts)
{
	struct mnt_list *mnt, *tmp;

	mnts_hash_mutex_lock();
	list_for_each_entry_safe(mnt, tmp, mnts, expire) {
		list_del_init(&mnt->expire);
		__mnts_put_mount(mnt);
	}
	mnts_hash_mutex_unlock();
}

struct tree_node *tree_host_root(struct exportinfo *exp)
{
	return tree_root(tree_host_ops, exp);
}

static struct tree_node *tree_host_new(void *ptr)
{
	struct tree_node *n = EXPORT_NODE(ptr);

	n->ops = tree_host_ops;
	n->left = NULL;
	n->right = NULL;

	return n;
}

static int tree_host_cmp(struct tree_node *n, void *ptr)
{
	struct exportinfo *n_exp = EXPORTINFO(n);
	size_t n_exp_len = strlen(n_exp->dir);
	struct exportinfo *exp = ptr;
	size_t exp_len = strlen(exp->dir);
	int eq;

	eq = strcmp(exp->dir, n_exp->dir);
	if (!eq) {
		error(LOGOPT_ANY, "duplicate entry %s ignored", exp->dir);
		return 0;
	}
	return (exp_len < n_exp_len) ? -1 : 1;
}

static void tree_host_free(struct tree_node *n)
{
	n->ops = NULL;
	n->left = NULL;
	n->right = NULL;
}

struct tree_node *tree_host_add_node(struct tree_node *root, struct exportinfo *exp)
{
	return tree_add_node(root, exp);
}

struct tree_node *tree_mapent_root(struct mapent *me)
{
	return tree_root(tree_mapent_ops, me);
}

static struct tree_node *tree_mapent_new(void *ptr)
{
	struct tree_node *n = MAPENT_NODE(ptr);

	n->ops = tree_mapent_ops;
	n->left = NULL;
	n->right = NULL;

	return n;
}

static int tree_mapent_cmp(struct tree_node *n, void *ptr)
{
	struct mapent *n_me = MAPENT(n);
	size_t n_me_len = n_me->len;
	struct mapent *me = ptr;
	size_t me_len = me->len;

	if (strncmp(me->key, n_me->key, n_me_len) == 0) {
		if (me_len < n_me_len)
			return -1;
		else if (me_len > n_me_len)
			return 1;
	}
	return strcmp(me->key, n_me->key);
}

static void tree_mapent_free(struct tree_node *n)
{
	n->ops = NULL;
	n->left = NULL;
	n->right = NULL;
}

int tree_mapent_add_node(struct mapent_cache *mc,
			 struct tree_node *root, struct mapent *me)
{
	struct tree_node *n;
	struct mapent *parent;

	n = tree_add_node(root, me);
	if (!n)
		return 0;

	MAPENT_SET_ROOT(me, root)

	/* Set the subtree parent */
	parent = cache_get_offset_parent(mc, me->key);
	if (!parent)
		MAPENT_SET_PARENT(me, root)
	else
		MAPENT_SET_PARENT(me, MAPENT_NODE(parent))

	return 1;
}

static inline int tree_mapent_is_root(struct mapent *oe)
{
	/* Offset "/" is a special case, it's looked up and mounted
	 * seperately because the offset tree may or may not have a
	 * real mount at the base and the triggers inside it need to
	 * be mounted in either case. Also the order requires the
	 * offset at the top of the (sub)tree to be handled after
	 * the traversal.
	 */
	return (oe->key[oe->len - 1] == '/' ||
	        MAPENT_ROOT(oe) == MAPENT_NODE(oe));
}

struct traverse_subtree_context {
	struct autofs_point *ap;
	struct tree_node *base;
	int strict;
};

static int tree_mapent_traverse_subtree(struct tree_node *n, tree_work_fn_t work, void *ptr)
{
	struct traverse_subtree_context *ctxt = ptr;
	struct mapent *oe = MAPENT(n);
	int ret = -1;

	if (n->left) {
		ret = tree_mapent_traverse_subtree(n->left, work, ctxt);
		if (!ret && ctxt->strict)
			goto done;
	}

	/* Node is not multi-mount root and is part of current subtree */
	if (!tree_mapent_is_root(oe) && MAPENT_PARENT(oe) == ctxt->base) {
		ret = work(n, ctxt);
		if (!ret && ctxt->strict)
			goto done;
	}

	if (n->right) {
		ret = tree_mapent_traverse_subtree(n->right, work, ctxt);
		if (!ret && ctxt->strict)
			goto done;
	}
done:
	return ret;
}

static int tree_mapent_delete_offset_tree(struct tree_node *root)
{
	struct mapent *me = MAPENT(root);
	unsigned int logopt = me->mc->ap->logopt;
	int ret = CHE_OK;

	if (root->left) {
		ret = tree_mapent_delete_offset_tree(root->left);
		if (!ret)
			return 0;
		root->left = NULL;
	}
	if (root->right) {
		ret = tree_mapent_delete_offset_tree(root->right);
		if (!ret)
			return 0;
		root->right = NULL;
	}

	/* Keep the owner of the multi-mount offset tree and clear
	 * the root and parent when done.
	 */
	if (MAPENT_ROOT(me) != MAPENT_NODE(me)) {
		struct tree_node *root = MAPENT_ROOT(me);
		char *key;

		key = strdup(me->key);
		if (!key) {
			char buf[MAX_ERR_BUF];
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, "strdup: %s", estr);
			return 0;
		}

		debug(logopt, "deleting offset key %s", key);

		/* cache_delete won't delete an active offset */
		MAPENT_SET_ROOT(me, NULL);
		ret = cache_delete(me->mc, key);
		if (ret != CHE_OK) {
			MAPENT_SET_ROOT(me, root);
			warn(logopt, "failed to delete offset %s", key);
		}
		free(key);
	} else {
		MAPENT_SET_ROOT(me, NULL);
		MAPENT_SET_PARENT(me, NULL);
	}

	return ret == CHE_OK ? 1 : 0;
}

int tree_mapent_delete_offsets(struct mapent_cache *mc, const char *key)
{
	unsigned int logopt = mc->ap->logopt;
	struct mapent *me;

	me = cache_lookup_distinct(mc, key);
	if (!me) {
		error(logopt,
		     "failed to find multi-mount root for key %s", key);
		return 0;
	}

	/* Not offset list owner */
	if (MAPENT_ROOT(me) != MAPENT_NODE(me)) {
		error(logopt,
		     "mapent for key %s is not multi-mount owner", key);
		return 0;
	}

	if (!tree_mapent_delete_offset_tree(MAPENT_ROOT(me))) {
		error(logopt,
		     "could not delete map entry offsets for key %s", key);
		return 0;
	}

	return 1;
}

static void tree_mapent_umount_mount(struct autofs_point *ap, const char *mp)
{
	if (is_mounted(mp, MNTS_ALL)) {
		if (umount(mp)) {
			error(ap->logopt, "error recovering from mount fail");
			error(ap->logopt, "cannot umount %s", mp);
		}
	}
}

static int tree_mapent_cleanup_offsets_work(struct tree_node *n, void *ptr)
{
	struct mapent *oe = MAPENT(n);
	struct traverse_subtree_context *ctxt = ptr;

	tree_mapent_umount_mount(ctxt->ap, oe->key);

	return 1;
}

void tree_mapent_cleanup_offsets(struct mapent *oe)
{
	struct tree_node *base = MAPENT_NODE(oe);
	struct traverse_subtree_context ctxt = {
		.ap = oe->mc->ap,
		.base = base,
		.strict = 0,
	};
	struct autofs_point *ap = oe->mc->ap;

	tree_mapent_traverse_subtree(base, tree_mapent_cleanup_offsets_work, &ctxt);

	/* Cleanup base mount after offsets have been cleaned up */
	if (*oe->key == '/')
		tree_mapent_umount_mount(ap, oe->key);
	else {
		char mp[PATH_MAX + 1];

		if (!mount_fullpath(mp, PATH_MAX, ap->path, ap->len, oe->key))
			error(ap->logopt, "mount path is too long");
		else
			tree_mapent_umount_mount(ap, mp);
	}
}

static int tree_mapent_rmdir_path_offset(struct autofs_point *ap, struct mapent *oe)
{
	struct mapent *mm_root = MAPENT(MAPENT_ROOT(oe));
	char *dir, *path;
	unsigned int split;
	int ret;

	if (ap->type == LKP_DIRECT)
		return rmdir_path(ap, oe->key, mm_root->dev);

	dir = strdup(oe->key);

	if (ap->flags & MOUNT_FLAG_GHOST)
		split = ap->len + mm_root->len + 1;
	else
		split = ap->len;

	dir[split] = '\0';
	path = &dir[split + 1];

	if (chdir(dir) == -1) {
		error(ap->logopt, "failed to chdir to %s", dir);
		free(dir);
		return -1;
	}

	ret = rmdir_path(ap, path, ap->dev);

	free(dir);

	if (chdir("/") == -1)
		error(ap->logopt, "failed to chdir to /");

	return ret;
}

static int tree_mapent_mount_offset(struct mapent *oe, void *ptr)
{
	struct traverse_subtree_context *ctxt = ptr;
	struct autofs_point *ap = ctxt->ap;
	int ret;

	debug(ap->logopt, "mount offset %s", oe->key);

	ret = mount_autofs_offset(ap, oe);
	if (ret < MOUNT_OFFSET_OK) {
		if (ret != MOUNT_OFFSET_IGNORE) {
			warn(ap->logopt, "failed to mount offset");
			return 0;
		} else {
			debug(ap->logopt,
			      "ignoring \"nohide\" trigger %s", oe->key);
			/*
			 * Ok, so we shouldn't modify the mapent but
			 * mount requests are blocked at a point above
			 * this and expire only uses the mapent key or
			 * holds the cache write lock.
			 */
			free(oe->mapent);
			oe->mapent = NULL;
		}
	}

	return 1;
}

static int tree_mapent_umount_offset(struct mapent *oe, void *ptr)
{
	struct traverse_subtree_context *ctxt = ptr;
	struct autofs_point *ap = ctxt->ap;
	int ret = 1;

	/*
	 * Check for and umount subtree offsets resulting from
	 * nonstrict mount fail.
	 */
	ret = tree_mapent_umount_offsets(oe);
	if (!ret)
		return 0;

	/*
	 * If an offset that has an active mount has been removed
	 * from the multi-mount we don't want to attempt to trigger
	 * mounts for it. Obviously this is because it has been
	 * removed, but less obvious is the potential strange
	 * behaviour that can result if we do try and mount it
	 * again after it's been expired. For example, if an NFS
	 * file system is no longer exported and is later umounted
	 * it can be mounted again without any error message but
	 * shows as an empty directory. That's going to confuse
	 * people for sure.
	 *
	 * If the mount cannot be umounted (the process is now
	 * using a stale mount) the offset needs to be invalidated
	 * so no further mounts will be attempted but the offset
	 * cache entry must remain so expires can continue to
	 * attempt to umount it. If the mount can be umounted and
	 * the offset is removed, at least for NFS we will get
	 * ESTALE errors when attempting list the directory.
	 */
	if (oe->ioctlfd != -1 ||
	    is_mounted(oe->key, MNTS_REAL)) {
		if (umount_ent(ap, oe->key)) {
			debug(ap->logopt,
			      "offset %s has active mount, invalidate",
			      oe->key);
			/*
			 * Ok, so we shouldn't modify the mapent but
			 * mount requests are blocked at a point above
			 * this and expire only uses the mapent key or
			 * holds the cache write lock.
			 */
			if (oe->mapent) {
				free(oe->mapent);
				oe->mapent = NULL;
			}
			return 0;
		}
	}

	/* Don't bother if there's noting to umount. */
	if (!is_mounted(oe->key, MNTS_AUTOFS))
		goto done;

	debug(ap->logopt, "umount offset %s", oe->key);

	if (umount_autofs_offset(ap, oe)) {
		warn(ap->logopt, "failed to umount offset");
		ret = 0;
	} else {
		struct stat st;
		int ret;

		if (!(oe->flags & MOUNT_FLAG_DIR_CREATED))
			goto done;

		/*
		 * An error due to partial directory removal is
		 * ok so only try and remount the offset if the
		 * actual mount point still exists.
		 */
		ret = tree_mapent_rmdir_path_offset(ap, oe);
		if (ret == -1 && !stat(oe->key, &st)) {
			ret = tree_mapent_mount_offset(oe, ctxt);
			/* But we did origianlly create this */
			oe->flags |= MOUNT_FLAG_DIR_CREATED;
		}
	}
done:
	return ret;
}

static int tree_mapent_mount_offsets_work(struct tree_node *n, void *ptr)
{
	struct traverse_subtree_context *ctxt = ptr;
	struct mapent *oe = MAPENT(n);
	struct mapent *mm_root = MAPENT(MAPENT_ROOT(oe));
	struct autofs_point *ap = ctxt->ap;
	int ret;

	if (!oe->mapent)
		return 1;

	/* Stale offset, no longer present in the mapent */
	if (oe->age != mm_root->age) {
		/* Best effort */
		tree_mapent_umount_offset(oe, ctxt);
		return 1;
	}

	ret = tree_mapent_mount_offset(oe, ctxt);

	/*
	 * If re-constructing a multi-mount it's necessary to walk
	 * into nested mounts, unlike the usual "mount only what's
	 * needed as you go" behavior.
	 */
	if (ap->state == ST_READMAP && ap->flags & MOUNT_FLAG_REMOUNT) {
		if (oe->ioctlfd != -1 ||
		    is_mounted(oe->key, MNTS_REAL))
			/* Best effort */
			tree_mapent_mount_offsets(oe, !ctxt->strict);
	}

	return (ctxt->strict ? ret : 1);
}

int tree_mapent_mount_offsets(struct mapent *oe, int nonstrict)
{
	struct tree_node *base = MAPENT_NODE(oe);
	struct traverse_subtree_context ctxt = {
		.ap = oe->mc->ap,
		.base = base,
		.strict = !nonstrict,
	};

	return tree_mapent_traverse_subtree(base,
				tree_mapent_mount_offsets_work, &ctxt);
}

static int tree_mapent_umount_offsets_work(struct tree_node *n, void *ptr)
{
	struct mapent *oe = MAPENT(n);

	return tree_mapent_umount_offset(oe, ptr);
}

int tree_mapent_umount_offsets(struct mapent *oe)
{
	struct tree_node *base = MAPENT_NODE(oe);
	struct autofs_point *ap = oe->mc->ap;
	struct traverse_subtree_context ctxt = {
		.ap = ap,
		.base = base,
		.strict = 1,
	};
	int ret;

	ret = tree_mapent_traverse_subtree(base,
				tree_mapent_umount_offsets_work, &ctxt);
	if (ret && tree_mapent_is_root(oe)) {
		char mp[PATH_MAX + 1];

		/*
		 * The map entry cache stores mapent keys. For indirect
		 * mount maps they are single direcory components so when
		 * one of these keys is the root of a multi-mount the mount
		 * path must be constructed.
		 */
		if (!mount_fullpath(mp, PATH_MAX, ap->path, ap->len, oe->key)) {
			error(ap->logopt, "mount path is too long");
			return 0;
		}

		/*
		 * Special case.
		 * If we can't umount the root container then we can't
		 * delete the offsets from the cache and we need to put
		 * the offset triggers back.
		 */
		if (is_mounted(mp, MNTS_REAL)) {
			info(ap->logopt, "unmounting dir = %s", mp);
			if (umount_ent(ap, mp)) {
				if (!tree_mapent_mount_offsets(oe, 1))
					warn(ap->logopt,
					     "failed to remount offset triggers");
				return 0;
			}
		}

		/* check for mounted mount entry and remove it if found */
		mnts_remove_mount(mp, MNTS_MOUNTED);

	}

	return ret;
}

/* From glibc decode_name() */
/* Since the values in a line are separated by spaces, a name cannot
 * contain a space.  Therefore some programs encode spaces in names
 * by the strings "\040".  We undo the encoding when reading an entry.
 * The decoding happens in place.
 */
static char *local_decode_name(char *buf)
{
	char *rp = buf;
	char *wp = buf;

	do {
		if (rp[0] == '\\' && rp[1] == '0' &&
		    rp[2] == '4' && rp[3] == '0') {
			/* \040 is a SPACE.  */
			*wp++ = ' ';
			rp += 3;
		} else if (rp[0] == '\\' && rp[1] == '0' &&
			   rp[2] == '1' && rp[3] == '1') {
			/* \011 is a TAB.  */
			*wp++ = '\t';
			rp += 3;
		} else if (rp[0] == '\\' && rp[1] == '0' &&
			   rp[2] == '1' && rp[3] == '2') {
			/* \012 is a NEWLINE.  */
			*wp++ = '\n';
			rp += 3;
		} else if (rp[0] == '\\' && rp[1] == '\\') {
			/*
			 * We have to escape \\ to be able to represent
			 * all characters.
			 */
			*wp++ = '\\';
			rp += 1;
		} else if (rp[0] == '\\' && rp[1] == '1' &&
			   rp[2] == '3' && rp[3] == '4') {
			/* \134 is also \\.  */
			*wp++ = '\\';
			rp += 3;
		} else
			*wp++ = *rp;
	} while (*rp++ != '\0');

	return buf;
}

/* From glibc getmntent_r() */
static struct mntent *
local_getmntent_r(FILE *tab, struct mntent *mnt, char *buf, int size)
{
	char *cp, *head;

	do {
		char *end_ptr;

		if (fgets(buf, size, tab) == NULL)
			return 0;

		end_ptr = strchr(buf, '\n');
		if (end_ptr != NULL) {
			while (end_ptr[-1] == ' ' || end_ptr[-1] == '\t')
				end_ptr--;
			*end_ptr = '\0';
		} else {
			/* Whole line was not read. Do it now but forget it. */
			char tmp[1024];
			while (fgets(tmp, sizeof tmp, tab) != NULL)
				if (strchr(tmp, '\n') != NULL)
					break;
		}

		head = buf + strspn(buf, " \t");
	/* skip empty lines and comment lines */
	} while (head[0] == '\0' || head[0] == '#');

	cp = strsep(&head, " \t");
	mnt->mnt_fsname = cp != NULL ? local_decode_name(cp) : (char *) "";
	if (head)
		head += strspn(head, " \t");
	cp = strsep(&head, " \t");
	mnt->mnt_dir = cp != NULL ? local_decode_name (cp) : (char *) "";
	if (head)
		head += strspn(head, " \t");
	cp = strsep(&head, " \t");
	mnt->mnt_type = cp != NULL ? local_decode_name (cp) : (char *) "";
	if (head)
		head += strspn (head, " \t");
	cp = strsep (&head, " \t");
	mnt->mnt_opts = cp != NULL ? local_decode_name (cp) : (char *) "";

	/* autofs doesn't need freq or passno */

	return mnt;
}

int unlink_mount_tree(struct autofs_point *ap, const char *mp)
{
	struct mnt_list *mnts, *mnt;
	int rv, ret = 1;

	errno = 0;
	mnts = get_mnt_list(mp, 1);
	if (!mnts) {
		if (errno)
			return 0;
		return 1;
	}

	for (mnt = mnts; mnt; mnt = mnt->next) {
		if (mnt->flags & MNTS_AUTOFS)
			rv = umount2(mnt->mp, MNT_DETACH);
		else
			rv = spawn_umount(ap->logopt, "-l", mnt->mp, NULL);
		if (rv == -1) {
			debug(ap->logopt,
			      "can't unlink %s from mount tree", mnt->mp);

			switch (errno) {
			case EINVAL:
				warn(ap->logopt,
				      "bad superblock or not mounted");
				break;

			case ENOENT:
			case EFAULT:
				ret = 0;
				warn(ap->logopt, "bad path for mount");
				break;
			}
		}
	}
	free_mnt_list(mnts);

	return ret;
}

/*
 * Get list of mounts under path in longest->shortest order
 */
struct mnt_list *get_mnt_list(const char *path, int include)
{
	FILE *tab;
	size_t pathlen = strlen(path);
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	struct mntent *mnt;
	struct mnt_list *ent, *mptr, *last;
	struct mnt_list *list = NULL;
	size_t len;

	if (!path || !pathlen || pathlen > PATH_MAX)
		return NULL;

	tab = open_fopen_r(_PROC_MOUNTS);
	if (!tab)
		return NULL;

	while ((mnt = local_getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		len = strlen(mnt->mnt_dir);

		if ((!include && len <= pathlen) ||
	  	     strncmp(mnt->mnt_dir, path, pathlen) != 0)
			continue;

		/* Not a subdirectory of requested mp? */
		/* mp_len == 1 => everything is subdir    */
		if (pathlen > 1 && len > pathlen &&
				mnt->mnt_dir[pathlen] != '/')
			continue;

		ent = malloc(sizeof(*ent));
		if (!ent) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		memset(ent, 0, sizeof(*ent));

		mptr = list;
		last = NULL;
		while (mptr) {
			if (len >= strlen(mptr->mp))
				break;
			last = mptr;
			mptr = mptr->next;
		}

		if (mptr == list)
			list = ent;
		else
			last->next = ent;

		ent->next = mptr;

		ent->mp = malloc(len + 1);
		if (!ent->mp) {
			endmntent(tab);
			free_mnt_list(list);
			return NULL;
		}
		strcpy(ent->mp, mnt->mnt_dir);

		if (!strcmp(mnt->mnt_type, "autofs"))
			ent->flags |= MNTS_AUTOFS;

		if (ent->flags & MNTS_AUTOFS) {
			if (strstr(mnt->mnt_opts, "indirect"))
				ent->flags |= MNTS_INDIRECT;
			else if (strstr(mnt->mnt_opts, "direct"))
				ent->flags |= MNTS_DIRECT;
			else if (strstr(mnt->mnt_opts, "offset"))
				ent->flags |= MNTS_OFFSET;
		}
	}
	fclose(tab);

	return list;
}

void free_mnt_list(struct mnt_list *list)
{
	struct mnt_list *next;

	if (!list)
		return;

	next = list;
	while (next) {
		struct mnt_list *this = next;

		next = this->next;

		if (this->mp)
			free(this->mp);

		free(this);
	}
}

static int table_is_mounted(const char *mp, unsigned int type)
{
	struct mntent *mnt;
	struct mntent mnt_wrk;
	char buf[PATH_MAX * 3];
	size_t mp_len = strlen(mp);
	struct stat st;
	FILE *tab;
	int ret;

	ret = stat(mp, &st);
	if (ret == -1) {
		if (errno == ENOENT) {
			/* Path does not exist */
			return 0;
		}
		ret = 0;
	}

	if (!mp || !mp_len || mp_len >= PATH_MAX)
		return 0;

	tab = open_fopen_r(_PROC_MOUNTS);
	if (!tab)
		return 0;

	while ((mnt = local_getmntent_r(tab, &mnt_wrk, buf, PATH_MAX * 3))) {
		size_t len = strlen(mnt->mnt_dir);

		if (type) {
			unsigned int autofs_fs;

			autofs_fs = !strcmp(mnt->mnt_type, "autofs");

			if (type & MNTS_REAL)
				if (autofs_fs)
					continue;

			if (type & MNTS_AUTOFS)
				if (!autofs_fs)
					continue;
		}

		if (mp_len == len && !strncmp(mp, mnt->mnt_dir, mp_len)) {
			ret = 1;
			break;
		}
	}
	fclose(tab);

	return ret;
}

static int ioctl_is_mounted(const char *mp, unsigned int type)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	unsigned int mounted;
	int ret;

	/* If the ioctl fails fall back to the potentially resource
	 * intensive mount table check.
	 */
	ret = ops->ismountpoint(LOGOPT_NONE, -1, mp, &mounted);
	if (ret == -1)
		return table_is_mounted(mp, type);

	if (mounted) {
		switch (type) {
		case MNTS_ALL:
			return 1;
		case MNTS_AUTOFS:
			return (mounted & DEV_IOCTL_IS_AUTOFS);
		case MNTS_REAL:
			return (mounted & DEV_IOCTL_IS_OTHER);
		}
	}
	return 0;
}

int is_mounted(const char *mp, unsigned int type)
{
	struct ioctl_ops *ops = get_ioctl_ops();

	if (ops->ismountpoint)
		return ioctl_is_mounted(mp, type);
	else
		return table_is_mounted(mp, type);
}

void set_tsd_user_vars(unsigned int logopt, uid_t uid, gid_t gid)
{
	struct thread_stdenv_vars *tsv;
	struct passwd pw;
	struct passwd *ppw = &pw;
	struct passwd **pppw = &ppw;
	struct group gr;
	struct group *pgr;
	struct group **ppgr;
	char *pw_tmp, *gr_tmp;
	int status, tmplen, grplen;

	/*
	 * Setup thread specific data values for macro
	 * substution in map entries during the mount.
	 * Best effort only as it must go ahead.
	 */

	tsv = malloc(sizeof(struct thread_stdenv_vars));
	if (!tsv) {
		error(logopt, "failed alloc tsv storage");
		return;
	}
	memset(tsv, 0, sizeof(struct thread_stdenv_vars));

	tsv->uid = uid;
	tsv->gid = gid;

	/* Try to get passwd info */

	/* sysconf may return -1 with unchanged errno to indicate unlimited
	 * size, same for the call for _SC_GETGR_R_SIZE_MAX  below
	 */
	errno = 0;
	tmplen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (tmplen < 0 && errno != 0) {
		error(logopt, "failed to get buffer size for getpwuid_r");
		goto free_tsv;
	}
	if (tmplen < 0)
		tmplen = 1024;	/* assume something reasonable */

	pw_tmp = malloc(tmplen + 1);
	if (!pw_tmp) {
		error(logopt, "failed to malloc buffer for getpwuid_r");
		goto free_tsv;
	}

	status = getpwuid_r(uid, ppw, pw_tmp, tmplen, pppw);
	if (status || !ppw) {
		error(logopt, "failed to get passwd info from getpwuid_r");
		free(pw_tmp);
		goto free_tsv;
	}

	tsv->user = strdup(pw.pw_name);
	if (!tsv->user) {
		error(logopt, "failed to malloc buffer for user");
		free(pw_tmp);
		goto free_tsv;
	}

	tsv->home = strdup(pw.pw_dir);
	if (!tsv->home) {
		error(logopt, "failed to malloc buffer for home");
		free(pw_tmp);
		goto free_tsv_user;
	}

	free(pw_tmp);

	/* Try to get group info */

	errno = 0;
	grplen = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (grplen < 0 && errno != 0) {
		error(logopt, "failed to get buffer size for getgrgid_r");
		goto free_tsv_home;
	}
	if (grplen < 0)
		grplen = 1024;

	gr_tmp = NULL;
	status = ERANGE;
#ifdef ENABLE_LIMIT_GETGRGID_SIZE
	if (!maxgrpbuf)
		maxgrpbuf = detached_thread_stack_size * 0.9;
#endif

	/* If getting the group name fails go on without it. It's
	 * used to set an environment variable for program maps
	 * which may or may not use it so it isn't critical to
	 * operation.
	 */

	tmplen = grplen;
	while (1) {
		char *tmp = realloc(gr_tmp, tmplen + 1);
		if (!tmp) {
			error(logopt, "failed to malloc buffer for getgrgid_r");
			goto no_group;
		}
		gr_tmp = tmp;
		pgr = &gr;
		ppgr = &pgr;
		status = getgrgid_r(gid, pgr, gr_tmp, tmplen, ppgr);
		if (status != ERANGE)
			break;
		tmplen *= 2;

		/* Don't tempt glibc to alloca() larger than is (likely)
		 * available on the stack if limit-getgrgid-size is enabled.
		 */
		if (!maxgrpbuf || (tmplen < maxgrpbuf))
			continue;

		/* Add a message so we know this happened */
		debug(logopt, "group buffer allocation would be too large");
		break;
	}

no_group:
	if (status || !pgr)
		error(logopt, "failed to get group info from getgrgid_r");
	else {
		tsv->group = strdup(gr.gr_name);
		if (!tsv->group)
			error(logopt, "failed to malloc buffer for group");
	}

	if (gr_tmp)
		free(gr_tmp);

	status = pthread_setspecific(key_thread_stdenv_vars, tsv);
	if (status) {
		error(logopt, "failed to set stdenv thread var");
		goto free_tsv_group;
	}

	return;

free_tsv_group:
	if (tsv->group)
		free(tsv->group);
free_tsv_home:
	free(tsv->home);
free_tsv_user:
	free(tsv->user);
free_tsv:
	free(tsv);
	return;
}

const char *mount_type_str(const unsigned int type)
{
	static const char *str_type[] = {
		"indirect",
		"direct",
		"offset"
	};
	unsigned int pos, i;

	for (pos = 0, i = type; pos < type_count; i >>= 1, pos++)
		if (i & 0x1)
			break;

	return (pos == type_count ? NULL : str_type[pos]);
}

void set_exp_timeout(struct autofs_point *ap,
		     struct map_source *source, time_t timeout)
{
	ap->exp_timeout = timeout;
	if (source)
		source->exp_timeout = timeout;
}

time_t get_exp_timeout(struct autofs_point *ap, struct map_source *source)
{
	time_t timeout = ap->exp_timeout;

	if (source && ap->type == LKP_DIRECT)
		timeout = source->exp_timeout;

	return timeout;
}

void notify_mount_result(struct autofs_point *ap,
			 const char *path, time_t timeout, const char *type)
{
	if (timeout)
		info(ap->logopt,
		    "mounted %s on %s with timeout %u, freq %u seconds",
		    type, path, (unsigned int) timeout,
		    (unsigned int) ap->exp_runfreq);
	else
		info(ap->logopt,
		     "mounted %s on %s with timeouts disabled",
		     type, path);

	return;
}

static int do_remount_direct(struct autofs_point *ap,
			     const unsigned int type, int fd, const char *path)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	int status = REMOUNT_SUCCESS;
	uid_t uid;
	gid_t gid;
	int ret;

	ops->requester(ap->logopt, fd, path, &uid, &gid);
	if (uid != -1 && gid != -1)
		set_tsd_user_vars(ap->logopt, uid, gid);

	ret = lookup_nss_mount(ap, NULL, path, strlen(path));
	if (ret) {
		unsigned int flags = MNTS_DIRECT|MNTS_MOUNTED;

		/* If it's an offset mount add a mount reference */
		if (type == t_offset)
			flags |= MNTS_OFFSET;

		mnts_set_mounted_mount(ap, path, flags);

		info(ap->logopt, "re-connected to %s", path);

		conditional_alarm_add(ap, ap->exp_runfreq);
	} else {
		status = REMOUNT_FAIL;
		info(ap->logopt, "failed to re-connect %s", path);
	}

	return status;
}

static int do_remount_indirect(struct autofs_point *ap, const unsigned int type, int fd, const char *path)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	int status = REMOUNT_SUCCESS;
	struct dirent **de;
	char buf[PATH_MAX + 1];
	uid_t uid;
	gid_t gid;
	unsigned int mounted;
	int n, size;

	n = scandir(path, &de, 0, alphasort);
	if (n < 0)
		return -1;

	size = sizeof(buf);

	while (n--) {
		int ret, len;

		if (strcmp(de[n]->d_name, ".") == 0 ||
		    strcmp(de[n]->d_name, "..") == 0) {
			free(de[n]);
			continue;
		}

		ret = cat_path(buf, size, path, de[n]->d_name);
		if (!ret) {
			do {
				free(de[n]);
			} while (n--);
			free(de);
			return -1;
		}

		ops->ismountpoint(ap->logopt, -1, buf, &mounted);
		if (!mounted) {
			struct dirent **de2;
			int i, j;

			i = j = scandir(buf, &de2, 0, alphasort);
			if (i < 0) {
				free(de[n]);
				continue;
			}
			while (i--)
				free(de2[i]);
			free(de2);
			if (j <= 2) {
				free(de[n]);
				continue;
			}
		}

		ops->requester(ap->logopt, fd, buf, &uid, &gid);
		if (uid != -1 && gid != -1)
			set_tsd_user_vars(ap->logopt, uid, gid);

		len = strlen(de[n]->d_name);

		ret = lookup_nss_mount(ap, NULL, de[n]->d_name, len);
		if (ret) {
			unsigned int flags = MNTS_INDIRECT|MNTS_MOUNTED;

			mnts_set_mounted_mount(ap, buf, flags);

			info(ap->logopt, "re-connected to %s", buf);

			conditional_alarm_add(ap, ap->exp_runfreq);
		} else {
			status = REMOUNT_FAIL;
			info(ap->logopt, "failed to re-connect %s", buf);
		}
		free(de[n]);
	}
	free(de);

	return status;
}

static int remount_active_mount(struct autofs_point *ap,
				struct mapent *me, const char *path, dev_t devid,
				const unsigned int type, int *ioctlfd)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	const char *str_type = mount_type_str(type);
	char buf[MAX_ERR_BUF];
	unsigned int mounted;
	time_t timeout;
	struct stat st;
	int fd;

	*ioctlfd = -1;

	/* Open failed, no mount present */
	fd = open_ioctlfd(ap, path, devid);
	if (fd == -1)
		return REMOUNT_OPEN_FAIL;

	if (!me)
		timeout = get_exp_timeout(ap, NULL);
	else
		timeout = get_exp_timeout(ap, me->source);

	/* Re-reading the map, set timeout and return */
	if (ap->state == ST_READMAP) {
		debug(ap->logopt, "already mounted, update timeout");
		ops->timeout(ap->logopt, fd, timeout);
		ops->close(ap->logopt, fd);
		return REMOUNT_READ_MAP;
	}

	debug(ap->logopt, "trying to re-connect to mount %s", path);

	/* Mounted so set pipefd and timeout etc. */
	if (ops->catatonic(ap->logopt, fd) == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "set catatonic failed: %s", estr);
		debug(ap->logopt, "couldn't re-connect to mount %s", path);
		ops->close(ap->logopt, fd);
		return REMOUNT_OPEN_FAIL;
	}
	if (ops->setpipefd(ap->logopt, fd, ap->kpipefd) == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "set pipefd failed: %s", estr);
		debug(ap->logopt, "couldn't re-connect to mount %s", path);
		ops->close(ap->logopt, fd);
		return REMOUNT_OPEN_FAIL;
	}
	ops->timeout(ap->logopt, fd, timeout);
	if (fstat(fd, &st) == -1) {
		error(ap->logopt,
		      "failed to stat %s mount %s", str_type, path);
		debug(ap->logopt, "couldn't re-connect to mount %s", path);
		ops->close(ap->logopt, fd);
		return REMOUNT_STAT_FAIL;
	}
	if (type == t_indirect)
		ap->dev = st.st_dev;
	else {
		if (strcmp(path, me->key)) {
			error(ap->logopt,
			      "mount point path mismatch, path %s mapent %s", path, me->key);
			debug(ap->logopt, "couldn't re-connect to mount %s", path);
			ops->close(ap->logopt, fd);
			return REMOUNT_STAT_FAIL;
		}
		me->dev = st.st_dev;
		me->ino = st.st_ino;
		cache_set_ino_index(me->mc, me);
	}
	notify_mount_result(ap, path, timeout, str_type);

	*ioctlfd = fd;

	/* Any mounts on or below? */
	if (ops->ismountpoint(ap->logopt, fd, path, &mounted) == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "ismountpoint %s failed: %s", path, estr);
		debug(ap->logopt, "couldn't re-connect to mount %s", path);
		ops->close(ap->logopt, fd);
		return REMOUNT_FAIL;
	}
	if (!mounted) {
		/*
		 * If we're an indirect mount we pass back the fd.
		 * But if were a direct or offset mount with no active
		 * mount we don't retain an open file descriptor.
		 */
		if (type != t_indirect) {
			ops->close(ap->logopt, fd);
			*ioctlfd = -1;
		}
	} else {
		/*
		 * What can I do if we can't remount the existing
		 * mount(s) (possibly a partial failure), everything
		 * following will be broken?
		 */
		if (type == t_indirect)
			do_remount_indirect(ap, type, fd, path);
		else
			do_remount_direct(ap, type, fd, path);
	}

	debug(ap->logopt, "re-connected to mount %s", path);

	return REMOUNT_SUCCESS;
}

int try_remount(struct autofs_point *ap, struct mapent *me, unsigned int type)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct mapent *mapent;
	const char *path;
	int ret, fd;
	dev_t devid;

	if (type == t_indirect)
		path = ap->path;
	else
		path = me->key;

	ret = ops->mount_device(ap->logopt, path, type, &devid);
	if (ret == -1 || ret == 0)
		return -1;

	ret = remount_active_mount(ap, me, path, devid, type, &fd);

	/*
	 * The directory must exist since we found a device
	 * number for the mount but we can't know if we created
	 * it or not. However, if this is an indirect mount with
	 * the nobrowse option we need to remove the mount point
	 * directory at umount anyway. Also, if this is an offset
	 * mount that's not within a real mount then we know we
	 * created it so we must remove it on expire for the mount
	 * to function.
	 */
	if (type == t_indirect) {
		if (ap->flags & MOUNT_FLAG_GHOST)
			ap->flags &= ~MOUNT_FLAG_DIR_CREATED;
		else
			ap->flags |= MOUNT_FLAG_DIR_CREATED;
		goto done;
	}

	me->flags &= ~MOUNT_FLAG_DIR_CREATED;
	mapent = IS_MM(me) ? MM_PARENT(me) : me;
	/* Direct or offset mount, key is full path */
	if (mapent->key[0] == '/') {
		if (!is_mounted(mapent->key, MNTS_REAL))
			me->flags |= MOUNT_FLAG_DIR_CREATED;
	} else {
		char *p_key = mapent->key;
		char mp[PATH_MAX + 1];
		int len;

		len = mount_fullpath(mp, PATH_MAX, ap->path, ap->len, p_key);
		if (len > PATH_MAX) {
			/* This should never happen due to earlier checks */
			error(ap->logopt, "mountpoint path too long");
			return 0;
		}

		if (!is_mounted(mp, MNTS_REAL))
			me->flags |= MOUNT_FLAG_DIR_CREATED;
	}
done:
	/*
	 * Either we opened the mount or we're re-reading the map.
	 * If we opened the mount and ioctlfd is not -1 we have
	 * a descriptor for the indirect mount so we need to
	 * record that in the mount point struct. Otherwise we're
	 * re-reading the map.
	*/
	if (ret == REMOUNT_READ_MAP)
		return 1;
	else if (ret == REMOUNT_SUCCESS) {
		if (fd != -1) {
			if (type == t_indirect)
				ap->ioctlfd = fd;
			else {
				if (type == t_offset &&
				    !is_mounted(me->key, MNTS_REAL)) {
					ops->close(ap->logopt, fd);
					fd = -1;
				}
				me->ioctlfd = fd;
			}
			return 1;
		}

		/* Indirect mount requires a valid fd */
		if (type != t_indirect)
			return 1;
	}

	/*
	 * Since we got the device number above a mount exists so
	 * any other failure warrants a failure return here.
	 */
	return 0;
}

/*
 * When exiting mounts need be set catatonic, regardless of whether they
 * are busy on not, to avoid a hang on access once the daemon has gone
 * away.
 */
static int set_mount_catatonic(struct autofs_point *ap, struct mapent *me, int ioctlfd)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	unsigned int opened = 0;
	const char *path;
	int fd;
	int err;
	dev_t dev;

	path = ap->path;
	dev = ap->dev;
	if (me && (ap->type == LKP_DIRECT || *me->key == '/')) {
		path = me->key;
		dev = me->dev;
	}

	if (ioctlfd >= 0)
		fd = ioctlfd;
	else if (me && me->ioctlfd >= 0)
		fd = me->ioctlfd;
	else {
		fd = open_ioctlfd(ap, path, dev);
		if (fd == -1)
			return (errno == ENOENT ? 0 : errno);
		opened = 1;
	}

	err = ops->catatonic(ap->logopt, fd);
	if (err == -1) {
		char buf[MAX_ERR_BUF];
		char *estr;

		err = errno;
		estr = strerror_r(err, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      "failed to set %s catatonic, error: %s",
		      path, estr);
		goto out;
	}

	debug(ap->logopt, "set %s catatonic", path);
out:
	if (opened)
		ops->close(ap->logopt, fd);

	return err;
}

static int set_offset_tree_catatonic_work(struct tree_node *n, void *ptr)
{
	struct mapent *me = MAPENT(n);
	struct autofs_point *ap = me->mc->ap;

	set_mount_catatonic(ap, me, me->ioctlfd);

	return 1;
}

static void set_offset_tree_catatonic(struct autofs_point *ap, struct mapent *me)
{
	tree_traverse_inorder(MAPENT_ROOT(me), set_offset_tree_catatonic_work, NULL);
}

void set_indirect_mount_tree_catatonic(struct autofs_point *ap)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me;

	if (!is_mounted(ap->path, MNTS_AUTOFS))
		return;

	map = entry->maps;
	while (map) {
		mc = map->mc;
		cache_readlock(mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			/* Skip negative map entries and wildcard entries */
			if (!me->mapent)
				goto next;

			if (!strcmp(me->key, "*"))
				goto next;

			/* Only need to set offset mounts catatonic */
			if (IS_MM(me) && IS_MM_ROOT(me))
				set_offset_tree_catatonic(ap, me);
next:
			me = cache_enumerate(mc, me);
		}
		cache_unlock(mc);
		map = map->next;
	}

	/* By the time this function is called ap->ioctlfd will have
	 * been closed so don't try and use it.
	 */
	set_mount_catatonic(ap, NULL, -1);

	return;
}

void set_direct_mount_tree_catatonic(struct autofs_point *ap, struct mapent *me)
{
	/* Set offset mounts catatonic for this mapent */
	if (IS_MM(me) && IS_MM_ROOT(me))
		set_offset_tree_catatonic(ap, me);
	set_mount_catatonic(ap, me, me->ioctlfd);
}

int umount_ent(struct autofs_point *ap, const char *path)
{
	unsigned int mounted;
	int rv;

	if (ap->state != ST_SHUTDOWN_FORCE)
		rv = spawn_umount(ap->logopt, path, NULL);
	else {
		/* We are doing a forced shutdown so unlink busy
		 * mounts */
		info(ap->logopt, "forcing umount of %s", path);
		rv = spawn_umount(ap->logopt, "-l", path, NULL);
	}

	mounted = is_mounted(path, MNTS_REAL);

	if (rv && (ap->state == ST_SHUTDOWN_FORCE || ap->state == ST_SHUTDOWN)) {
		/*
		 * Verify that we actually unmounted the thing.  This is a
		 * belt and suspenders approach to not eating user data.
		 * We have seen cases where umount succeeds, but there is
		 * still a file system mounted on the mount point.  How
		 * this happens has not yet been determined, but we want to
		 * make sure to return failure here, if that is the case,
		 * so that we do not try to call rmdir_path on the
		 * directory.
		 */
		if (mounted) {
			crit(ap->logopt,
			     "the umount binary reported that %s was "
			     "unmounted, but there is still something "
			     "mounted on this path.", path);
			mounted = -1;
		}
	}

	/* If mount is gone remove it from mounted mounts list. */
	if (!mounted)
		mnts_remove_mount(path, MNTS_MOUNTED);

	return mounted;
}

int umount_amd_ext_mount(struct autofs_point *ap, const char *path)
{
	struct ext_mount *em;
	char *umount = NULL;
	char *mp;
	int rv = 1;

	pthread_mutex_lock(&ext_mount_hash_mutex);

	em = ext_mount_lookup(path);
	if (!em) {
		pthread_mutex_unlock(&ext_mount_hash_mutex);
		goto out;
	}
	mp = strdup(em->mp);
	if (!mp) {
		pthread_mutex_unlock(&ext_mount_hash_mutex);
		goto out;
	}
	if (em->umount) {
		umount = strdup(em->umount);
		if (!umount) {
			pthread_mutex_unlock(&ext_mount_hash_mutex);
			free(mp);
			goto out;
		}
	}

	pthread_mutex_unlock(&ext_mount_hash_mutex);

	if (umount) {
		char *prog;
		char **argv;
		int argc = -1;

		prog = NULL;
		argv = NULL;

		argc = construct_argv(umount, &prog, &argv);
		if (argc == -1)
			goto done;

		if (!ext_mount_remove(mp)) {
			rv =0;
			goto out_free;
		}

		rv = spawnv(ap->logopt, prog, (const char * const *) argv);
		if (rv == -1 || (WIFEXITED(rv) && WEXITSTATUS(rv)))
			error(ap->logopt,
			     "failed to umount program mount at %s", mp);
		else {
			rv = 0;
			debug(ap->logopt, "umounted program mount at %s", mp);
			rmdir_path(ap, mp, ap->dev);
		}
out_free:
		free_argv(argc, (const char **) argv);

		goto done;
	}

	if (ext_mount_remove(mp)) {
		rv = umount_ent(ap, mp);
		if (rv)
			error(ap->logopt,
			      "failed to umount external mount %s", mp);
		else
			debug(ap->logopt, "umounted external mount %s", mp);
	}
done:
	if (umount)
		free(umount);
	free(mp);
out:
	return rv;
}
