/* ----------------------------------------------------------------------- *
 *
 *  direct.c - Linux automounter direct mount handling
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
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sched.h>

#define INCLUDE_PENDING_FUNCTIONS
#include "automount.h"

/* Attribute to create detached thread */
extern pthread_attr_t th_attr_detached;

struct mnt_params {
	char *options;
};

pthread_key_t key_mnt_direct_params;
pthread_key_t key_mnt_offset_params;
pthread_once_t key_mnt_params_once = PTHREAD_ONCE_INIT;

static void key_mnt_params_destroy(void *arg)
{
	struct mnt_params *mp;

	mp = (struct mnt_params *) arg;
	if (mp->options)
		free(mp->options);
	free(mp);
	return;
}

static void key_mnt_params_init(void)
{
	int status;

	status = pthread_key_create(&key_mnt_direct_params, key_mnt_params_destroy);
	if (status)
		fatal(status);

	status = pthread_key_create(&key_mnt_offset_params, key_mnt_params_destroy);
	if (status)
		fatal(status);

	return;
}

static void mnts_cleanup(void *arg)
{
	struct list_head *mnts = (struct list_head *) arg;
	mnts_put_expire_list(mnts);
}

int do_umount_autofs_direct(struct autofs_point *ap, struct mapent *me)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct mapent_cache *mc = me->mc;
	char buf[MAX_ERR_BUF];
	int ioctlfd = -1, rv, left, retries;
	char key[PATH_MAX + 1];
	struct mapent *tmp;
	int opened = 0;

	if (me->len > PATH_MAX) {
		error(ap->logopt, "path too long");
		return 1;
	}
	strcpy(key, me->key);

	cache_unlock(mc);
	left = umount_multi(ap, key, 0);
	cache_readlock(mc);
	tmp = cache_lookup_distinct(mc, key);
	if (tmp != me) {
		error(ap->logopt, "key %s no longer in mapent cache", key);
		return -1;
	}
	if (left) {
		warn(ap->logopt, "could not unmount %d dirs under %s",
		     left, me->key);
		return 1;
	}

	if (me->ioctlfd != -1) {
		if (ap->state == ST_READMAP &&
		    is_mounted(me->key, MNTS_REAL)) {
			error(ap->logopt,
			      "attempt to umount busy direct mount %s",
			      me->key);
			return 1;
		}
		ioctlfd = me->ioctlfd;
	} else {
		ioctlfd = open_ioctlfd(ap, me->key, me->dev);
		if (ioctlfd == -1)
			return 1;
		opened = 1;
	}

	if (ioctlfd >= 0) {
		unsigned int status = 1;

		rv = ops->askumount(ap->logopt, ioctlfd, &status);
		if (rv) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, "ioctl failed: %s", estr);
			/* The ioctl failed so this probably won't
			 * work either but since we opened it here
			 * try anyway. We should set these catatonic
			 * too but ....
			 */
			if (opened)
				ops->close(ap->logopt, ioctlfd);
			return 1;
		} else if (!status) {
			if (ap->state != ST_SHUTDOWN_FORCE) {
				error(ap->logopt,
				      "ask umount returned busy for %s",
				      me->key);
				if (opened)
					ops->close(ap->logopt, ioctlfd);
				return 1;
			} else {
				me->ioctlfd = -1;
				ops->close(ap->logopt, ioctlfd);
				goto force_umount;
			}
		}
		me->ioctlfd = -1;
		ops->close(ap->logopt, ioctlfd);
	} else {
		error(ap->logopt,
		      "couldn't get ioctl fd for direct mount %s", me->key);
		return 1;
	}

	sched_yield();

	retries = UMOUNT_RETRIES;
	while ((rv = umount(me->key)) == -1 && retries--) {
		struct timespec tm = {0, 50000000};
		if (errno != EBUSY)
			break;
		nanosleep(&tm, NULL);
	}

	if (rv == -1) {
		switch (errno) {
		case ENOENT:
		case EINVAL:
			warn(ap->logopt, "mount point %s does not exist",
			      me->key);
			return 0;
			break;
		case EBUSY:
			warn(ap->logopt, "mount point %s is in use", me->key);
			if (ap->state == ST_SHUTDOWN_FORCE)
				goto force_umount;
			else {
				if (ap->state != ST_READMAP)
					set_direct_mount_tree_catatonic(ap, me);
				return 0;
			}
			break;
		case ENOTDIR:
			error(ap->logopt, "mount point is not a directory");
			return 0;
			break;
		}
		return 1;
	}

force_umount:
	if (rv != 0) {
		info(ap->logopt, "forcing umount of direct mount %s", me->key);
		rv = umount2(me->key, MNT_DETACH);
	} else
		info(ap->logopt, "umounted direct mount %s", me->key);

	if (!rv && me->flags & MOUNT_FLAG_DIR_CREATED) {
		if  (rmdir(me->key) == -1) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			warn(ap->logopt, "failed to remove dir %s: %s",
			     me->key, estr);
		}
	}
	return rv;
}

int umount_autofs_direct(struct autofs_point *ap)
{
	struct map_source *map;
	struct mapent_cache *nc, *mc;
	struct mapent *me, *ne;

	nc = ap->entry->master->nc;
	cache_readlock(nc);
	pthread_cleanup_push(cache_lock_cleanup, nc);
	map = ap->entry->maps;
	while (map) {
		mc = map->mc;
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_readlock(mc);
restart:
		me = cache_enumerate(mc, NULL);
		while (me) {
			int error;

			ne = cache_lookup_distinct(nc, me->key);
			if (ne && map->master_line > ne->age) {
				me = cache_enumerate(mc, me);
				continue;
			}

			/* The daemon is exiting so ...
			 * If we get a fail here we must make our
			 * best effort to set the direct mount trigger
			 * catatonic regardless of the reason for the
			 * failed umount.
			 */
			error = do_umount_autofs_direct(ap, me);
			/* cache became invalid, restart */
			if (error == -1)
				goto restart;
			if (!error)
				goto done;

			if (ap->state != ST_READMAP)
				set_direct_mount_tree_catatonic(ap, me);
done:
			me = cache_enumerate(mc, me);
		}
		pthread_cleanup_pop(1);
		map = map->next;
	}
	pthread_cleanup_pop(1);

	if (ap->pipefd >= 0)
		close(ap->pipefd);
	if (ap->kpipefd >= 0) {
		close(ap->kpipefd);
		ap->kpipefd = -1;
	}

	return 0;
}

int do_mount_autofs_direct(struct autofs_point *ap,
			   struct mapent *me, time_t timeout)
{
	const char *str_direct = mount_type_str(t_direct);
	struct ioctl_ops *ops = get_ioctl_ops();
	struct mnt_params *mp;
	struct stat st;
	int status, ret, ioctlfd;
	const char *map_name;
	time_t runfreq;
	int err;

	if (timeout) {
		/* Calculate the expire run frequency */
		runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;
		if (ap->exp_runfreq)
			ap->exp_runfreq = min(ap->exp_runfreq, runfreq);
		else
			ap->exp_runfreq = runfreq;
	}

	if (ops->version && !do_force_unlink) {
		ap->flags |= MOUNT_FLAG_REMOUNT;
		ret = try_remount(ap, me, t_direct);
		ap->flags &= ~MOUNT_FLAG_REMOUNT;
		if (ret == 1)
			return 0;
		if (ret == 0)
			return -1;
	} else {
		/* I don't remember why this is here for the force
		 * unlink case. I don't think it should be but I may
		 * have done it for a reason so keep it for the unlink
		 * and continue case but not for the unlink and exit
		 * case.
		 */
		if (!(do_force_unlink & UNLINK_AND_EXIT) &&
		    ap->state == ST_READMAP && is_mounted(me->key, MNTS_ALL)) {
			time_t tout = get_exp_timeout(ap, me->source);
			int save_ioctlfd, ioctlfd;

			save_ioctlfd = ioctlfd = me->ioctlfd;

			if (ioctlfd == -1)
				ioctlfd = open_ioctlfd(ap, me->key, me->dev);

			if (ioctlfd < 0) {
				error(ap->logopt,
				     "failed to create ioctl fd for %s",
				     me->key);
				return 0;
			}

			ops->timeout(ap->logopt, ioctlfd, NULL, tout);

			if (save_ioctlfd == -1)
				ops->close(ap->logopt, ioctlfd);

			return 0;
		}

		ret = unlink_mount_tree(ap, me->key);
		if (!ret) {
			error(ap->logopt,
			     "already mounted as other than autofs "
			     "or failed to unlink entry in tree");
			goto out_err;
		}

		if (do_force_unlink & UNLINK_AND_EXIT)
			return -1;

		if (me->ioctlfd != -1) {
			error(ap->logopt, "active direct mount %s", me->key);
			return -1;
		}
	}

	status = pthread_once(&key_mnt_params_once, key_mnt_params_init);
	if (status)
		fatal(status);

	mp = pthread_getspecific(key_mnt_direct_params);
	if (!mp) {
		mp = (struct mnt_params *) malloc(sizeof(struct mnt_params));
		if (!mp) {
			crit(ap->logopt,
			  "mnt_params value create failed for direct mount %s",
			  ap->path);
			return 0;
		}
		mp->options = NULL;

		status = pthread_setspecific(key_mnt_direct_params, mp);
		if (status) {
			free(mp);
			fatal(status);
		}
	}

	if (!mp->options) {
		mp->options = make_options_string(ap->path,
				ap->kpipefd, str_direct, ap->flags);
		if (!mp->options)
			return 0;
	}

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(me->key, mp_mode) < 0) {
		if (errno != EEXIST && errno != EROFS) {
			crit(ap->logopt,
			     "failed to create mount directory %s", me->key);
			return -1;
		}
		/* If we recieve an error, and it's EEXIST or EROFS we know
		   the directory was not created. */
		me->flags &= ~MOUNT_FLAG_DIR_CREATED;
	} else {
		/* No errors so the directory was successfully created */
		me->flags |= MOUNT_FLAG_DIR_CREATED;
	}

	map_name = me->mc->map->argv[0];

	ret = mount(map_name, me->key, "autofs", MS_MGC_VAL, mp->options);
	if (ret) {
		crit(ap->logopt, "failed to mount autofs path %s", me->key);
		goto out_err;
	}

	ret = stat(me->key, &st);
	if (ret == -1) {
		error(ap->logopt,
		      "failed to stat direct mount trigger %s", me->key);
		goto out_umount;
	}
	me->dev = st.st_dev;
	me->ino = st.st_ino;

	if (ap->mode && (err = chmod(me->key, ap->mode)))
		warn(ap->logopt, "failed to change mode of %s", me->key);

	ioctlfd = open_ioctlfd(ap, me->key, me->dev);
	if (ioctlfd < 0) {
		crit(ap->logopt, "failed to create ioctl fd for %s", me->key);
		goto out_umount;
	}

	ops->timeout(ap->logopt, ioctlfd, NULL, timeout);
	notify_mount_result(ap, me->key, timeout, str_direct);
	cache_set_ino_index(me->mc, me);
	ops->close(ap->logopt, ioctlfd);

	debug(ap->logopt, "mounted trigger %s", me->key);

	return 0;

out_umount:
	/* TODO: maybe force umount (-l) */
	umount(me->key);
out_err:
	if (me->flags & MOUNT_FLAG_DIR_CREATED)
		rmdir(me->key);

	return -1;
}

int mount_autofs_direct(struct autofs_point *ap)
{
	struct map_source *map;
	struct mapent_cache *nc, *mc;
	struct mapent *me, *ne, *nested;
	time_t now = monotonic_time(NULL);

	if (strcmp(ap->path, "/-")) {
		error(ap->logopt, "expected direct map, exiting");
		return -1;
	}

	/* TODO: check map type */
	if (lookup_nss_read_map(ap, NULL, now))
		lookup_prune_cache(ap, now);
	else {
		error(ap->logopt, "failed to read direct map");
		return -1;
	}

	pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
	master_source_readlock(ap->entry);
	nc = ap->entry->master->nc;
	map = ap->entry->maps;
	while (map) {
		time_t timeout;
		/*
		 * Only consider map sources that have been read since
		 * the map entry was last updated.
		 */
		if (ap->entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		timeout = get_exp_timeout(ap, map);
		cache_readlock(mc);
		pthread_cleanup_push(cache_lock_cleanup, mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			cache_writelock(nc);
			ne = cache_lookup_distinct(nc, me->key);
			if (ne) {
				unsigned int ne_age = ne->age;

				cache_unlock(nc);
				if (map->master_line < ne_age) {
					/* TODO: check return, locking me */
					do_mount_autofs_direct(ap, me, timeout);
				}
				me = cache_enumerate(mc, me);
				continue;
			}

			nested = cache_partial_match(nc, me->key);
			if (!nested)
				cache_unlock(nc);
			else {
				cache_delete(nc, nested->key);
				cache_unlock(nc);
				error(ap->logopt,
				   "removing invalid nested null entry %s",
				   nested->key);
			}

			/* TODO: check return, locking me */
			do_mount_autofs_direct(ap, me, timeout);

			me = cache_enumerate(mc, me);
		}
		pthread_cleanup_pop(1);
		map = map->next;
	}
	pthread_cleanup_pop(1);

	return 0;
}

int umount_autofs_offset(struct autofs_point *ap, struct mapent *me)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	char buf[MAX_ERR_BUF];
	int ioctlfd = -1, rv = 1, retries;
	int opened = 0;

	if (me->ioctlfd != -1) {
		if (is_mounted(me->key, MNTS_REAL)) {
			error(ap->logopt,
			      "attempt to umount busy offset %s", me->key);
			return 1;
		}
		ioctlfd = me->ioctlfd;
	} else {
		/* offset isn't mounted, return success and try to recover */
		if (!is_mounted(me->key, MNTS_AUTOFS)) {
			debug(ap->logopt,
			      "offset %s not mounted",
			      me->key);
			return 0;
		}
		ioctlfd = open_ioctlfd(ap, me->key, me->dev);
		if (ioctlfd == -1)
			return 1;
		opened = 1;
	}

	if (ioctlfd >= 0) {
		unsigned int status = 1;

		rv = ops->askumount(ap->logopt, ioctlfd, &status);
		if (rv) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			logerr("ioctl failed: %s", estr);
			if (opened && ioctlfd != -1)
				ops->close(ap->logopt, ioctlfd);
			return 1;
		} else if (!status) {
			if (ap->state != ST_SHUTDOWN_FORCE) {
				if (ap->shutdown)
					error(ap->logopt,
					     "ask umount returned busy for %s",
					     me->key);
				if (opened && ioctlfd != -1)
					ops->close(ap->logopt, ioctlfd);
				return 1;
			} else {
				me->ioctlfd = -1;
				ops->catatonic(ap->logopt, ioctlfd);
				ops->close(ap->logopt, ioctlfd);
				goto force_umount;
			}
		}
		me->ioctlfd = -1;
		ops->catatonic(ap->logopt, ioctlfd);
		ops->close(ap->logopt, ioctlfd);
	} else {
		struct stat st;
		char *estr;
		int save_errno = errno;

		/* Non existent directory on remote fs - no mount */
		if (stat(me->key, &st) == -1 && errno == ENOENT)
			return 0;

		estr = strerror_r(save_errno, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      "couldn't get ioctl fd for offset %s: %s",
		      me->key, estr);
		goto force_umount;
	}

	sched_yield();

	retries = UMOUNT_RETRIES;
	while ((rv = umount(me->key)) == -1 && retries--) {
		struct timespec tm = {0, 50000000};
		if (errno != EBUSY)
			break;
		nanosleep(&tm, NULL);
	}

	if (rv == -1) {
		switch (errno) {
		case ENOENT:
			warn(ap->logopt, "mount point does not exist");
			return 0;
			break;
		case EBUSY:
			error(ap->logopt, "mount point %s is in use", me->key);
			if (ap->state != ST_SHUTDOWN_FORCE)
				return 1;
			break;
		case ENOTDIR:
			error(ap->logopt, "mount point is not a directory");
			return 0;
			break;
		}
		goto force_umount;
	}

force_umount:
	if (rv != 0) {
		info(ap->logopt, "forcing umount of offset mount %s", me->key);
		rv = umount2(me->key, MNT_DETACH);
	} else
		info(ap->logopt, "umounted offset mount %s", me->key);

	return rv;
}

int mount_autofs_offset(struct autofs_point *ap, struct mapent *me)
{
	const char *str_offset = mount_type_str(t_offset);
	struct ioctl_ops *ops = get_ioctl_ops();
	char buf[MAX_ERR_BUF];
	struct mnt_params *mp;
	time_t timeout = get_exp_timeout(ap, me->source);
	struct stat st;
	int ioctlfd, status, ret;
	const char *hosts_map_name = "-hosts";
	const char *map_name = hosts_map_name;
	const char *type;
	struct mnt_list *mnt;

	if (ops->version && ap->flags & MOUNT_FLAG_REMOUNT) {
		ret = try_remount(ap, me, t_offset);
		if (ret == 1)
			return MOUNT_OFFSET_OK;
		/* Offset mount not found, fall thru and try to mount it */
		if (!(ret == -1 && errno == ENOENT))
			return MOUNT_OFFSET_FAIL;
	} else {
		if (is_mounted(me->key, MNTS_AUTOFS)) {
			if (ap->state != ST_READMAP)
				warn(ap->logopt,
				     "trigger %s already mounted", me->key);
			mnt = mnts_add_mount(ap, me->key, MNTS_OFFSET);
			if (!mnt)
				error(ap->logopt,
				      "failed to add offset mount %s to mounted list",
				      me->key);
			return MOUNT_OFFSET_OK;
		}

		if (me->ioctlfd != -1) {
			error(ap->logopt, "active offset mount %s", me->key);
			return MOUNT_OFFSET_FAIL;
		}
	}

	status = pthread_once(&key_mnt_params_once, key_mnt_params_init);
	if (status)
		fatal(status);

	mp = pthread_getspecific(key_mnt_offset_params);
	if (!mp) {
		mp = (struct mnt_params *) malloc(sizeof(struct mnt_params));
		if (!mp) {
			crit(ap->logopt,
			  "mnt_params value create failed for offset mount %s",
			  me->key);
			return MOUNT_OFFSET_OK;
		}
		mp->options = NULL;

		status = pthread_setspecific(key_mnt_offset_params, mp);
		if (status) {
			free(mp);
			fatal(status);
		}
	}

	if (!mp->options) {
		mp->options = make_options_string(ap->path,
				ap->kpipefd, str_offset, ap->flags);
		if (!mp->options)
			return MOUNT_OFFSET_OK;
	}

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(me->key, mp_mode) < 0) {
		if (errno == EEXIST) {
			/*
			 * If the mount point directory is a real mount
			 * and it isn't the root offset then it must be
			 * a mount that has been automatically mounted by
			 * the kernel NFS client.
			 */
			if (!IS_MM_ROOT(me) &&
			    is_mounted(me->key, MNTS_REAL))
				return MOUNT_OFFSET_IGNORE;

			/* 
			 * If we recieve an error, and it's EEXIST
			 * we know the directory was not created.
			 */
			me->flags &= ~MOUNT_FLAG_DIR_CREATED;
		} else if (errno == EACCES) {
			/*
			 * We require the mount point directory to exist when
			 * installing multi-mount triggers into a host
			 * filesystem.
			 *
			 * If it doesn't exist it is not a valid part of the
			 * mount heirachy.
			 */
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			debug(ap->logopt,
			     "can't create mount directory: %s, %s",
			     me->key, estr);
			return MOUNT_OFFSET_FAIL;
		} else {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			crit(ap->logopt,
			     "failed to create mount directory: %s, %s",
			     me->key, estr);
			return MOUNT_OFFSET_FAIL;
		}
	} else {
		/* No errors so the directory was successfully created */
		me->flags |= MOUNT_FLAG_DIR_CREATED;
	}

	debug(ap->logopt,
	      "calling mount -t autofs " SLOPPY " -o %s automount %s",
	      mp->options, me->key);

	type = ap->entry->maps->type;
	if (!type || strcmp(ap->entry->maps->type, "hosts"))
		map_name = me->mc->map->argv[0];

	ret = mount(map_name, me->key, "autofs", MS_MGC_VAL, mp->options);
	if (ret) {
		crit(ap->logopt,
		     "failed to mount offset trigger %s at %s",
		     me->key, me->key);
		goto out_err;
	}

	ret = stat(me->key, &st);
	if (ret == -1) {
		int save_errno = errno;

		error(ap->logopt,
		     "failed to stat direct mount trigger %s", me->key);
		if (save_errno != ENOENT)
			goto out_umount;
		goto out_err;
	}
	me->dev = st.st_dev;
	me->ino = st.st_ino;

	ioctlfd = open_ioctlfd(ap, me->key, me->dev);
	if (ioctlfd < 0)
		goto out_umount;

	ops->timeout(ap->logopt, ioctlfd, NULL, timeout);
	cache_set_ino_index(me->mc, me);
	notify_mount_result(ap, me->key, timeout, str_offset);
	ops->close(ap->logopt, ioctlfd);

	debug(ap->logopt, "mounted trigger %s", me->key);

	return MOUNT_OFFSET_OK;

out_umount:
	umount(me->key);
out_err:
	if (stat(me->key, &st) == 0 && me->flags & MOUNT_FLAG_DIR_CREATED)
		 rmdir_path(ap, me->key, st.st_dev);

	return MOUNT_OFFSET_FAIL;
}

void *expire_proc_direct(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct mnt_list *mnt;
	LIST_HEAD(mnts);
	struct expire_args *ea;
	struct expire_args ec;
	struct autofs_point *ap;
	struct mapent *me = NULL;
	unsigned int how;
	int ioctlfd, cur_state;
	int status, ret, left;

	ea = (struct expire_args *) arg;

	status = pthread_mutex_lock(&ea->mutex);
	if (status)
		fatal(status);

	ap = ec.ap = ea->ap;
	how = ea->how;
	ec.status = -1;

	ea->signaled = 1;
	status = pthread_cond_signal(&ea->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_unlock(&ea->mutex);
	if (status)
		fatal(status);

	pthread_cleanup_push(expire_cleanup, &ec);

	left = 0;

	/* Get the list of real mounts and expire them if possible */
	mnts_get_expire_list(&mnts, ap);
	if (list_empty(&mnts))
		goto done;
	pthread_cleanup_push(mnts_cleanup, &mnts);
	list_for_each_entry(mnt, &mnts, expire) {
		/*
		 * All direct mounts must be present in the map
		 * entry cache.
		 */
		pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
		master_source_readlock(ap->entry);
		me = lookup_source_mapent(ap, mnt->mp, LKP_DISTINCT);
		pthread_cleanup_pop(1);
		if (!me)
			continue;

		if (mnt->flags & (MNTS_AUTOFS|MNTS_OFFSET)) {
			struct stat st;
			int ioctlfd;

			cache_unlock(me->mc);

			/*
			 * If we have submounts check if this path lives below
			 * one of them and pass on state change.
			 */
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
			if (mnt->flags & MNTS_AUTOFS) {
				master_notify_submount(ap, mnt->mp, ap->state);
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}

			if (me->ioctlfd == -1) {
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}

			/* It's got a mount, just send the expire. */
			if (is_mounted(me->key, MNTS_REAL))
				goto cont;

			/*
			 * Maybe a manual umount, repair.
			 * It will take ap->exp_timeout/4 for us to relaize
			 * this so user must still use USR1 signal to close
			 * the open file handle for mounts atop multi-mount
			 * triggers. There is no way that I'm aware of to
			 * avoid maintaining a file handle for control
			 * functions as once it's mounted all opens are
			 * directed to the mount not the trigger.
			 */

			/* Check for manual umount */
			cache_writelock(me->mc);
			if (me->ioctlfd != -1 && 
			    fstat(me->ioctlfd, &st) != -1 &&
			    !count_mounts(ap, mnt->mp, st.st_dev)) {
				ops->close(ap->logopt, me->ioctlfd);
				me->ioctlfd = -1;
				cache_unlock(me->mc);
				mnts_remove_mount(mnt->mp, MNTS_MOUNTED);
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}
			cache_unlock(me->mc);
cont:
			ioctlfd = me->ioctlfd;

			ret = ops->expire(ap->logopt, ioctlfd, mnt->mp, how);
			if (ret == 1) {
				left++;
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}

			pthread_setcancelstate(cur_state, NULL);
			continue;
		}

		if (me->ioctlfd >= 0) {
			/* Real mounts have an open ioctl fd */
			ioctlfd = me->ioctlfd;
			cache_unlock(me->mc);
		} else {
			cache_unlock(me->mc);
			continue;
		}

		if (ap->state == ST_EXPIRE || ap->state == ST_PRUNE)
			pthread_testcancel();

		debug(ap->logopt, "send expire to trigger %s", mnt->mp);

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
		ret = ops->expire(ap->logopt, ioctlfd, mnt->mp, how);
		if (ret == 1)
			left++;
		pthread_setcancelstate(cur_state, NULL);
	}
	pthread_cleanup_pop(1);

	if (left)
		debug(ap->logopt, "%d remaining in %s", left, ap->path);
done:
	ec.status = left;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	pthread_cleanup_pop(1);
	pthread_setcancelstate(cur_state, NULL);

	return NULL;
}

static void expire_send_fail(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt = arg;
	struct autofs_point *ap = mt->ap;
	ops->send_fail(ap->logopt,
		       mt->ioctlfd, mt->wait_queue_token, -ENOENT);
}

static void *do_expire_direct(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *args, mt;
	struct autofs_point *ap;
	size_t len;
	int status, state;

	args = (struct pending_args *) arg;

	pending_mutex_lock(args);

	memcpy(&mt, args, sizeof(struct pending_args));

	ap = mt.ap;

	args->signaled = 1;
	status = pthread_cond_signal(&args->cond);
	if (status)
		fatal(status);

	pending_mutex_unlock(args);

	pthread_cleanup_push(expire_send_fail, &mt);

	len = _strlen(mt.name, KEY_MAX_LEN);
	if (!len) {
		warn(ap->logopt, "direct key path too long %s", mt.name);
		/* TODO: force umount ?? */
		pthread_exit(NULL);
	}

	status = do_expire(ap, mt.name, len);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status)
		ops->send_fail(ap->logopt,
			       mt.ioctlfd, mt.wait_queue_token, -ENOENT);
	else {
		struct mapent *me;
		cache_writelock(mt.mc);
		me = cache_lookup_distinct(mt.mc, mt.name);
		if (me)
			me->ioctlfd = -1;
		cache_unlock(mt.mc);
		ops->send_ready(ap->logopt, mt.ioctlfd, mt.wait_queue_token);
		ops->close(ap->logopt, mt.ioctlfd);
	}
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);

	return NULL;
}

int handle_packet_expire_direct(struct autofs_point *ap, autofs_packet_expire_direct_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct map_source *map;
	struct mapent_cache *mc = NULL;
	struct mapent *me = NULL;
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	pthread_t thid;
	struct timespec wait;
	int status, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	/*
	 * This is a bit of a big deal.
	 * If we can't find the path and the map entry then
	 * we can't send a notification back to the kernel.
	 * Hang results.
	 *
	 * OTOH there is a mount so there should be a path
	 * and since it got mounted we have to trust that
	 * there is an entry in the cache.
	 */
	master_source_writelock(ap->entry);
	map = ap->entry->maps;
	while (map) {
		mc = map->mc;
		cache_writelock(mc);
		me = cache_lookup_ino(mc, pkt->dev, pkt->ino);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}

	if (!me || me->len >= PATH_MAX) {
		/*
		 * Shouldn't happen as we have been sent this following
		 * successful thread creation and lookup.
		 */
		if (!me)
			crit(ap->logopt, "can't find map entry for (%lu,%lu)",
			    (unsigned long) pkt->dev, (unsigned long) pkt->ino);
		else {
			cache_unlock(mc);
			crit(ap->logopt, "lookup key is too long");
		}
		master_source_unlock(ap->entry);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	/* Can't expire it if it isn't mounted */
	if (me->ioctlfd == -1) {
		int ioctlfd;

		ioctlfd = open_ioctlfd(ap, me->key, me->dev);
		if (ioctlfd == -1) {
			cache_unlock(mc);
			master_source_unlock(ap->entry);
			pthread_setcancelstate(state, NULL);
			return 1;
		}
		ops->send_ready(ap->logopt, ioctlfd, pkt->wait_queue_token);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       me->ioctlfd, pkt->wait_queue_token, -ENOMEM);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	pending_cond_init(mt);

	status = pthread_mutex_init(&mt->mutex, NULL);
	if (status)
		fatal(status);

	mt->ap = ap;
	mt->ioctlfd = me->ioctlfd;
	mt->mc = mc;
	strcpy(mt->name, me->key);
	mt->dev = me->dev;
	mt->type = NFY_EXPIRE;
	mt->wait_queue_token = pkt->wait_queue_token;

	debug(ap->logopt, "token %ld, name %s",
		  (unsigned long) pkt->wait_queue_token, mt->name);

	pending_mutex_lock(mt);

	status = pthread_create(&thid, &th_attr_detached, do_expire_direct, mt);
	if (status) {
		error(ap->logopt, "expire thread create failed");
		ops->send_fail(ap->logopt,
			       mt->ioctlfd, pkt->wait_queue_token, -status);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		pending_mutex_unlock(mt);
		pending_cond_destroy(mt);
		pending_mutex_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	cache_unlock(mc);
	master_source_unlock(ap->entry);

	pthread_cleanup_push(free_pending_args, mt);
	pthread_cleanup_push(pending_mutex_destroy, mt);
	pthread_cleanup_push(pending_cond_destroy, mt);
	pthread_cleanup_push(pending_mutex_unlock, mt);
	pthread_setcancelstate(state, NULL);

	mt->signaled = 0;
	while (!mt->signaled) {
		clock_gettime(CLOCK_MONOTONIC, &wait);
		wait.tv_sec += 2;
		status = pthread_cond_timedwait(&mt->cond, &mt->mutex, &wait);
		if (status && status != ETIMEDOUT)
			fatal(status);
	}

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return 0;
}

static void mount_send_status(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt = arg;
	struct autofs_point *ap = mt->ap;

	if (mt->status)
		ops->send_fail(ap->logopt, mt->ioctlfd,
			       mt->wait_queue_token, mt->status);
	else
		ops->send_ready(ap->logopt,
				mt->ioctlfd, mt->wait_queue_token);
	ops->close(ap->logopt, mt->ioctlfd);
}

static void *do_mount_direct(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *args, mt;
	struct autofs_point *ap;
	struct mapent *me;
	struct stat st;
	int status, state;

	args = (struct pending_args *) arg;

	pending_mutex_lock(args);

	memcpy(&mt, args, sizeof(struct pending_args));

	ap = mt.ap;

	set_thread_mount_request_log_id(&mt);

	args->signaled = 1;
	status = pthread_cond_signal(&args->cond);
	if (status)
		fatal(status);

	pending_mutex_unlock(args);

	mt.status = 0;
	pthread_cleanup_push(mount_send_status, &mt);

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	if (defaults_get_mount_verbose()) {
		pid_t ppid = log_pidinfo(ap, mt.pid, "requestor");
		if (ppid > 0)
			log_pidinfo(ap, ppid, "parent");
	}

	status = fstat(mt.ioctlfd, &st);
	if (status != 0 || !S_ISDIR(st.st_mode) || st.st_dev != mt.dev) {
		error(ap->logopt,
		     "direct trigger not valid or already mounted %s",
		     mt.name);
		mt.status = -EINVAL;
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	pthread_setcancelstate(state, NULL);

	info(ap->logopt, "attempting to mount entry %s", mt.name);

	set_tsd_user_vars(ap->logopt, mt.uid, mt.gid);

	status = lookup_nss_mount(ap, NULL, mt.name, mt.len);
	/*
	 * Direct mounts are always a single mount. If it fails there's
	 * nothing to undo so just complain
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status) {
		struct mnt_list *sbmnt;
		struct statfs fs;
		unsigned int close_fd = 0;
		unsigned int flags = MNTS_DIRECT|MNTS_MOUNTED;

		sbmnt = mnts_find_submount(mt.name);
		if (statfs(mt.name, &fs) == -1 ||
		   (fs.f_type == AUTOFS_SUPER_MAGIC && !sbmnt))
			close_fd = 1;
		if (sbmnt)
			mnts_put_mount(sbmnt);
		cache_writelock(mt.mc);
		if ((me = cache_lookup_distinct(mt.mc, mt.name))) {
			/*
			 * Careful here, we need to leave the file handle open
			 * for direct mount multi-mounts with no real mount at
			 * their base so they will be expired.
			 */
			if (close_fd && IS_MM_ROOT(me))
				close_fd = 0;
			if (!close_fd)
				me->ioctlfd = mt.ioctlfd;
			if (IS_MM(me) && !IS_MM_ROOT(me))
				flags |= MNTS_OFFSET;
		}
		ops->send_ready(ap->logopt, mt.ioctlfd, mt.wait_queue_token);
		cache_unlock(mt.mc);
		if (close_fd)
			ops->close(ap->logopt, mt.ioctlfd);

		info(ap->logopt, "mounted %s", mt.name);

		mnts_set_mounted_mount(ap, mt.name, flags);

		conditional_alarm_add(ap, ap->exp_runfreq);
	} else {
		/* TODO: get mount return status from lookup_nss_mount */
		ops->send_fail(ap->logopt,
			       mt.ioctlfd, mt.wait_queue_token, -ENOENT);
		ops->close(ap->logopt, mt.ioctlfd);
		info(ap->logopt, "failed to mount %s", mt.name);

		/* If this is a multi-mount subtree mount failure
		 * ensure the tree continues to expire.
		 */
		cache_readlock(mt.mc);
		me = cache_lookup_distinct(mt.mc, mt.name);
		if (me && IS_MM(me) && !IS_MM_ROOT(me))
			conditional_alarm_add(ap, ap->exp_runfreq);
		cache_unlock(mt.mc);
	}
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);

	return NULL;
}

int handle_packet_missing_direct(struct autofs_point *ap, autofs_packet_missing_direct_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct map_source *map;
	struct mapent_cache *mc = NULL;
	struct mapent *me = NULL;
	pthread_t thid;
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	int status = 0;
	struct timespec wait;
	int ioctlfd, state;
	unsigned int kver_major = get_kver_major();
	unsigned int kver_minor = get_kver_minor();

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	master_mutex_lock();

	/*
	 * If our parent is a direct or offset mount that has been
	 * covered by a mount and another lookup occurs after the
	 * mount but before the device and inode are set in the
	 * cache entry we will not be able to find the mapent. So
	 * we must take the source writelock to ensure the parent
	 * has mount is complete before we look for the entry.
	 *
	 * Since the vfs-automount kernel changes we can now block
	 * on covered mounts during mount tree construction so a
	 * write lock is no longer needed. So we now can handle a
	 * wider class of recursively define mount lookups.
	 */
	if (kver_major > 5 || (kver_major == 5 && kver_minor > 1))
		master_source_readlock(ap->entry);
	else
		master_source_writelock(ap->entry);
	map = ap->entry->maps;
	while (map) {
		/*
		 * Only consider map sources that have been read since
		 * the map entry was last updated.
		 */
		if (ap->entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		cache_readlock(mc);
		me = cache_lookup_ino(mc, pkt->dev, pkt->ino);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}

	if (!me) {
		/*
		 * Shouldn't happen as the kernel is telling us
		 * someone has walked on our mount point.
		 */
		logerr("can't find map entry for (%lu,%lu)",
		    (unsigned long) pkt->dev, (unsigned long) pkt->ino);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	if (me->ioctlfd != -1) {
		/* Maybe someone did a manual umount, clean up ! */
		close(me->ioctlfd);
		me->ioctlfd = -1;
	}

	ioctlfd = open_ioctlfd(ap, me->key, me->dev);
	if (ioctlfd == -1) {
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		crit(ap->logopt, "failed to create ioctl fd for %s", me->key);
		/* TODO:  how do we clear wait q in kernel ?? */
		return 1;
	}

	debug(ap->logopt, "token %ld, name %s, request pid %u",
		  (unsigned long) pkt->wait_queue_token, me->key, pkt->pid);

	/* Ignore packet if we're trying to shut down */
	if (ap->shutdown || ap->state == ST_SHUTDOWN_FORCE) {
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -ENOENT);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	/* Check if we recorded a mount fail for this key */
	if (me->status >= monotonic_time(NULL)) {
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -ENOENT);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	if (me->len >= PATH_MAX) {
		error(ap->logopt, "direct mount path too long %s", me->key);
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -ENAMETOOLONG);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, "malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -ENOMEM);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}
	memset(mt, 0, sizeof(struct pending_args));

	pending_cond_init(mt);

	status = pthread_mutex_init(&mt->mutex, NULL);
	if (status)
		fatal(status);

	pending_mutex_lock(mt);

	mt->ap = ap;
	mt->ioctlfd = ioctlfd;
	mt->mc = mc;
	strcpy(mt->name, me->key);
	mt->len = me->len;
	mt->dev = me->dev;
	mt->type = NFY_MOUNT;
	mt->uid = pkt->uid;
	mt->gid = pkt->gid;
	mt->pid = pkt->pid;
	mt->wait_queue_token = pkt->wait_queue_token;

	status = pthread_create(&thid, &th_attr_detached, do_mount_direct, mt);
	if (status) {
		error(ap->logopt, "missing mount thread create failed");
		ops->send_fail(ap->logopt,
			       ioctlfd, pkt->wait_queue_token, -status);
		ops->close(ap->logopt, ioctlfd);
		cache_unlock(mc);
		master_source_unlock(ap->entry);
		master_mutex_unlock();
		pending_mutex_unlock(mt);
		pending_cond_destroy(mt);
		pending_mutex_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	cache_unlock(mc);
	master_source_unlock(ap->entry);

	master_mutex_unlock();

	pthread_cleanup_push(free_pending_args, mt);
	pthread_cleanup_push(pending_mutex_destroy, mt);
	pthread_cleanup_push(pending_cond_destroy, mt);
	pthread_cleanup_push(pending_mutex_unlock, mt);
	pthread_setcancelstate(state, NULL);

	mt->signaled = 0;
	while (!mt->signaled) {
		clock_gettime(CLOCK_MONOTONIC, &wait);
		wait.tv_sec += 2;
		status = pthread_cond_timedwait(&mt->cond, &mt->mutex, &wait);
		if (status && status != ETIMEDOUT)
			fatal(status);
	}

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return 0;
}

