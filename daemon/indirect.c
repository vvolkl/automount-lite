/* ----------------------------------------------------------------------- *
 *
 *  indirect.c - Linux automounter indirect mount handling
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
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sched.h>

#define INCLUDE_PENDING_FUNCTIONS
#include "automount.h"

/* Attribute to create detached thread */
extern pthread_attr_t th_attr_detached;

static int do_mount_autofs_indirect(struct autofs_point *ap)
{
	const char *str_indirect = mount_type_str(t_indirect);
	struct ioctl_ops *ops = get_ioctl_ops();
	time_t timeout = get_exp_timeout(ap, ap->entry->maps);
	char *options = NULL;
	const char *hosts_map_name = "-hosts";
	const char *map_name = hosts_map_name;
	const char *type;
	struct stat st;
	int ret;
	int err;

	/* If the map is being shared the exp_timeout can't be inherited
	 * from the map source since it may be different so the autofs
	 * point exp_runfreq must have already been set.
	 */
	if (ap->entry->maps->ref <= 1)
		ap->exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;

	if (ops->version && !do_force_unlink) {
		ap->flags |= MOUNT_FLAG_REMOUNT;
		ret = try_remount(ap, NULL, t_indirect);
		ap->flags &= ~MOUNT_FLAG_REMOUNT;
		if (ret == 1)
			return 0;
		if (ret == 0)
			return -1;
	} else {
		ret = unlink_mount_tree(ap, ap->path);
		if (!ret) {
			error(ap->logopt,
			      "already mounted as other than autofs "
			      "or failed to unlink entry in tree");
			goto out_err;
		}

		if (do_force_unlink & UNLINK_AND_EXIT)
			return -1;
	}

	options = make_options_string(ap->path,
				ap->kpipefd, str_indirect, ap->flags);
	if (!options) {
		error(ap->logopt, "options string error");
		goto out_err;
	}

	/* In case the directory doesn't exist, try to mkdir it */
	if (mkdir_path(ap->path, mp_mode) < 0) {
		if (errno != EEXIST && errno != EROFS) {
			crit(ap->logopt,
			     "failed to create autofs directory %s",
			     ap->path);
			goto out_err;
		}
		/* If we recieve an error, and it's EEXIST or EROFS we know
		   the directory was not created. */
		ap->flags &= ~MOUNT_FLAG_DIR_CREATED;
	} else {
		/* No errors so the directory was successfully created */
		ap->flags |= MOUNT_FLAG_DIR_CREATED;
	}

	type = ap->entry->maps->type;
	if (!type || strcmp(ap->entry->maps->type, "hosts"))
		map_name = ap->entry->maps->argv[0];

	ret = mount(map_name, ap->path, "autofs", MS_MGC_VAL, options);
	if (ret) {
		crit(ap->logopt,
		     "failed to mount autofs at %s", ap->path);
		goto out_rmdir;
	}

	free(options);
	options = NULL;

	ret = stat(ap->path, &st);
	if (ret == -1) {
		crit(ap->logopt,
		     "failed to stat mount for autofs path %s", ap->path);
		goto out_umount;
	}
	ap->dev = st.st_dev;	/* Device number for mount point checks */

	if (ap->mode && (err = chmod(ap->path, ap->mode)))
		warn(ap->logopt, "failed to change mode of %s", ap->path);

	ap->ioctlfd = open_ioctlfd(ap, ap->path, ap->dev);
	if (ap->ioctlfd == -1) {
		crit(ap->logopt,
		     "failed to create ioctl fd for autofs path %s", ap->path);
		goto out_umount;
	}

	ops->timeout(ap->logopt, ap->ioctlfd, timeout);
	notify_mount_result(ap, ap->path, timeout, str_indirect);

	return 0;

out_umount:
	umount(ap->path);
out_rmdir:
	if (ap->flags & MOUNT_FLAG_DIR_CREATED)
		rmdir(ap->path);
out_err:
	if (options)
		free(options);
	close(ap->pipefd);
	close(ap->kpipefd);

	return -1;
}

int mount_autofs_indirect(struct autofs_point *ap)
{
	time_t now = monotonic_time(NULL);
	int status;
	int map;

	/* Don't read the map if the unlink and exit option has been
	 * given. do_mount_autofs_indirect() will return -1 if this
	 * option has been given so there's no need to do anything
	 * else.
	 */

	/* TODO: read map, determine map type is OK */
	if (!(do_force_unlink & UNLINK_AND_EXIT)) {
		if (lookup_nss_read_map(ap, NULL, now))
			lookup_prune_cache(ap, now);
		else {
			error(ap->logopt, "failed to read map for %s", ap->path);
			return -1;
		}
	}

	status = do_mount_autofs_indirect(ap);
	if (status < 0)
		return -1;

	map = lookup_ghost(ap);
	if (map & LKP_FAIL) {
		if (map & LKP_DIRECT) {
			error(ap->logopt,
			      "bad map format,found direct, "
			      "expected indirect exiting");
		} else {
			error(ap->logopt, "failed to load map, exiting");
		}
		/* TODO: Process cleanup ?? */
		return -1;
	}

	if (map & LKP_NOTSUP)
		ap->flags &= ~MOUNT_FLAG_GHOST;

	return 0;
}

void close_mount_fds(struct autofs_point *ap)
{
	/*
	 * Since submounts look after themselves the parent never knows
	 * it needs to close the ioctlfd for offset mounts so we have
	 * to do it here. If the cache entry isn't found then there aren't
	 * any offset mounts.
	 */
	if (ap->submount)
		lookup_source_close_ioctlfd(ap->parent, ap->path);

	if (ap->pipefd >= 0)
		close(ap->pipefd);

	if (ap->kpipefd >= 0)
		close(ap->kpipefd);

	return;
}

int umount_autofs_indirect(struct autofs_point *ap)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	char buf[MAX_ERR_BUF];
	int rv, retries;
	unsigned int unused;

	/* If we are trying to shutdown make sure we can umount */
	rv = ops->askumount(ap->logopt, ap->ioctlfd, &unused);
	if (rv == -1) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("ioctl failed: %s", estr);
		return 1;
	} else if (!unused) {
#if defined(ENABLE_IGNORE_BUSY_MOUNTS) || defined(ENABLE_FORCED_SHUTDOWN)
		if (!ap->shutdown)
			return 1;
		error(ap->logopt, "ask umount returned busy %s", ap->path);
#else
		return 1;
#endif
	}

	ops->close(ap->logopt, ap->ioctlfd);
	ap->ioctlfd = -1;
	sched_yield();

	retries = UMOUNT_RETRIES;
	while ((rv = umount(ap->path)) == -1 && retries--) {
		struct timespec tm = {0, 50000000};
		if (errno != EBUSY)
			break;
		nanosleep(&tm, NULL);
	}

	if (rv == -1) {
		switch (errno) {
		case ENOENT:
		case EINVAL:
			error(ap->logopt,
			      "mount point %s does not exist", ap->path);
			close_mount_fds(ap);
			return 0;
			break;
		case EBUSY:
			debug(ap->logopt,
			      "mount point %s is in use", ap->path);
			if (ap->state == ST_SHUTDOWN_FORCE) {
				close_mount_fds(ap);
				goto force_umount;
			} else {
				/*
				 * If the umount returns EBUSY there may be
				 * a mount request in progress so we need to
				 * recover unless we have been explicitly
				 * asked to shutdown and configure option
				 * ENABLE_IGNORE_BUSY_MOUNTS is enabled.
				 */
#ifdef ENABLE_IGNORE_BUSY_MOUNTS
				if (ap->shutdown) {
					close_mount_fds(ap);
					return 0;
				}
#endif
				ap->ioctlfd = open_ioctlfd(ap, ap->path, ap->dev);
				if (ap->ioctlfd < 0) {
					warn(ap->logopt,
					     "could not recover autofs path %s",
					     ap->path);
					close_mount_fds(ap);
					return 0;
				}
			}
			break;
		case ENOTDIR:
			error(ap->logopt, "mount point is not a directory");
			close_mount_fds(ap);
			return 0;
			break;
		}
		return 1;
	}

	/*
	 * We have successfully umounted the mount so we now close
	 * the descriptors. The kernel end of the kernel pipe will
	 * have been put during the umount super block cleanup.
	 */
	close_mount_fds(ap);

force_umount:
	if (rv != 0) {
		warn(ap->logopt,
		     "forcing umount of indirect mount %s", ap->path);
		rv = umount2(ap->path, MNT_DETACH);
	} else {
		info(ap->logopt, "umounting indirect mount %s succeeded", ap->path);
		if (ap->submount)
			rm_unwanted(ap, ap->path, 1);
	}

	return rv;
}

static void mnts_cleanup(void *arg)
{
	struct list_head *mnts = (struct list_head *) arg;
	mnts_put_expire_list(mnts);
}

void *expire_proc_indirect(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct autofs_point *ap;
	struct mnt_list *mnt;
	LIST_HEAD(mnts);
	struct mapent *me;
	struct expire_args *ea;
	struct expire_args ec;
	unsigned int how;
	int offsets, submnts, count;
	int ioctlfd, cur_state;
	int status, ret, left;
	int retries;

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
		char *ind_key;
		int ret;

		if (mnt->flags & (MNTS_AUTOFS|MNTS_OFFSET)) {
			/*
			 * If we have submounts check if this path lives below
			 * one of them and pass on the state change.
			 */
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
			if (mnt->flags & MNTS_AUTOFS) {
				master_notify_submount(ap, mnt->mp, ap->state);
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}

			/* An offset without a real mount, check for manual umount */
			if (mnt->flags & MNTS_OFFSET &&
			    !is_mounted(mnt->mp, MNTS_REAL)) {
				struct mnt_list *sbmnt;
				struct map_source *map;
				struct mapent_cache *mc = NULL;
				struct stat st;

				/* Don't touch submounts */
				sbmnt = mnts_find_submount(mnt->mp);
				if (sbmnt) {
					mnts_put_mount(sbmnt);
					pthread_setcancelstate(cur_state, NULL);
					continue;
				}

				master_source_writelock(ap->entry);

				map = ap->entry->maps;
				while (map) {
					mc = map->mc;
					cache_writelock(mc);
					me = cache_lookup_distinct(mc, mnt->mp);
					if (me)
						break;
					cache_unlock(mc);
					map = map->next;
				}

				if (!mc || !me) {
					master_source_unlock(ap->entry);
					pthread_setcancelstate(cur_state, NULL);
					continue;
				}

				if (me->ioctlfd == -1) {
					cache_unlock(mc);
					master_source_unlock(ap->entry);
					pthread_setcancelstate(cur_state, NULL);
					continue;
				}

				/* Check for manual umount */
				if (fstat(me->ioctlfd, &st) == -1 ||
				    !count_mounts(ap, me->key, st.st_dev)) {
					ops->close(ap->logopt, me->ioctlfd);
					me->ioctlfd = -1;
				}

				cache_unlock(mc);
				master_source_unlock(ap->entry);
				pthread_setcancelstate(cur_state, NULL);
				continue;
			}
			pthread_setcancelstate(cur_state, NULL);
		}

		if (ap->state == ST_EXPIRE || ap->state == ST_PRUNE)
			pthread_testcancel();

		/*
		 * If the mount corresponds to an offset trigger then
		 * the key is the path, otherwise it's the last component.
		 */
		ind_key = strrchr(mnt->mp, '/');
		if (ind_key)
			ind_key++;

		/*
		 * If me->key starts with a '/' and it's not an autofs
		 * filesystem it's a nested mount and we need to use
		 * the ioctlfd of the mount to send the expire.
		 * Otherwise it's a top level indirect mount (possibly
		 * with offsets in it) and we use the usual ioctlfd.
		 */
		pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
		master_source_readlock(ap->entry);
		me = lookup_source_mapent(ap, mnt->mp, LKP_DISTINCT);
		if (!me && ind_key)
			me = lookup_source_mapent(ap, ind_key, LKP_NORMAL);
		pthread_cleanup_pop(1);

		ioctlfd = ap->ioctlfd;
		if (me) {
			if (*me->key == '/')
				ioctlfd = me->ioctlfd;
			cache_unlock(me->mc);
		}

		debug(ap->logopt, "expire %s", mnt->mp);

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
		ret = ops->expire(ap->logopt, ioctlfd, mnt->mp, how);
		if (ret == 1)
			left++;
		pthread_setcancelstate(cur_state, NULL);
	}

	/*
	 * If there are no more real mounts left we could still
	 * have some offset mounts with no '/' offset or symlinks
	 * so we need to umount or unlink them here.
	 *
	 * The dentry info last_used field is set to 'now' when a
	 * dentry is selected for expire so that it isn't immediately
	 * selected again if the expire fails. But this can't work
	 * for immediate expires so the count_mounts() function must
	 * be used to limit the number of expire iterations.
	 */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	if (how == AUTOFS_EXP_IMMEDIATE)
		retries = count_mounts(ap, ap->path, ap->dev);
	else
		retries = -1;
	while (retries--) {
		ret = ops->expire(ap->logopt, ap->ioctlfd, ap->path, how);
		if (ret != 0 && errno == EAGAIN)
			break;
		if (ret == 1)
			left++;
	}
	pthread_setcancelstate(cur_state, NULL);
	pthread_cleanup_pop(1);

	count = offsets = submnts = 0;
	mnts_get_expire_list(&mnts, ap);
	pthread_cleanup_push(mnts_cleanup, &mnts);
	/* Are there any real mounts left */
	list_for_each_entry(mnt, &mnts, expire) {
		if (!(mnt->flags & MNTS_AUTOFS))
			count++;
		else {
			if (mnt->flags & MNTS_INDIRECT)
				submnts++;
			else
				offsets++;
		}
	}
	pthread_cleanup_pop(1);

	if (submnts)
		debug(ap->logopt,
		     "%d submounts remaining in %s", submnts, ap->path);

	/* 
	 * EXPIRE_MULTI is synchronous, so we can be sure (famous last
	 * words) the umounts are done by the time we reach here
	 */
	if (count)
		debug(ap->logopt, "%d remaining in %s", count, ap->path);
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
		       ap->ioctlfd, mt->wait_queue_token, -ENOENT);
}

static void *do_expire_indirect(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *args, mt;
	struct autofs_point *ap;
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

	status = do_expire(mt.ap, mt.name, mt.len);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status)
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, mt.wait_queue_token, -status);
	else
		ops->send_ready(ap->logopt,
				ap->ioctlfd, mt.wait_queue_token);
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);

	return NULL;
}

int handle_packet_expire_indirect(struct autofs_point *ap, autofs_packet_expire_indirect_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *mt;
	char buf[MAX_ERR_BUF];
	pthread_t thid;
	struct timespec wait;
	int status, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	debug(ap->logopt, "token %ld, name %s",
		  (unsigned long) pkt->wait_queue_token, pkt->name);

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -ENOMEM);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

	pending_cond_init(mt);

	status = pthread_mutex_init(&mt->mutex, NULL);
	if (status)
		fatal(status);

	mt->ap = ap;
	strncpy(mt->name, pkt->name, pkt->len);
	mt->name[pkt->len] = '\0';
	mt->len = pkt->len;
	mt->wait_queue_token = pkt->wait_queue_token;

	pending_mutex_lock(mt);

	status = pthread_create(&thid, &th_attr_detached, do_expire_indirect, mt);
	if (status) {
		error(ap->logopt, "expire thread create failed");
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -status);
		pending_mutex_unlock(mt);
		pending_cond_destroy(mt);
		pending_mutex_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

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
		ops->send_fail(ap->logopt, ap->ioctlfd,
			       mt->wait_queue_token, mt->status);
	else
		ops->send_ready(ap->logopt,
				ap->ioctlfd, mt->wait_queue_token);
}

static void *do_mount_indirect(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	struct pending_args *args, mt;
	struct autofs_point *ap;
	char buf[PATH_MAX + 1];
	struct stat st;
	int len, status, state;

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

	len = ncat_path(buf, sizeof(buf), ap->path, mt.name, mt.len);
	if (!len) {
		crit(ap->logopt, "path to be mounted is to long");
		mt.status = -ENAMETOOLONG;
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	status = lstat(buf, &st);
	if (status != -1 && !(S_ISDIR(st.st_mode) && st.st_dev == mt.dev)) {
		error(ap->logopt,
		      "indirect trigger not valid or already mounted %s", buf);
		pthread_setcancelstate(state, NULL);
		pthread_exit(NULL);
	}

	pthread_setcancelstate(state, NULL);

	info(ap->logopt, "attempting to mount entry %s", buf);

	set_tsd_user_vars(ap->logopt, mt.uid, mt.gid);

	status = lookup_nss_mount(ap, NULL, mt.name, mt.len);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	if (status) {
		unsigned int flags = MNTS_INDIRECT|MNTS_MOUNTED;

		ops->send_ready(ap->logopt,
				ap->ioctlfd, mt.wait_queue_token);

		info(ap->logopt, "mounted %s", buf);

		mnts_set_mounted_mount(ap, mt.name, flags);

		conditional_alarm_add(ap, ap->exp_runfreq);
	} else {
		/* TODO: get mount return status from lookup_nss_mount */
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, mt.wait_queue_token, -ENOENT);
		info(ap->logopt, "failed to mount %s", buf);
	}
	pthread_setcancelstate(state, NULL);

	pthread_cleanup_pop(0);

	return NULL;
}

int handle_packet_missing_indirect(struct autofs_point *ap, autofs_packet_missing_indirect_t *pkt)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	pthread_t thid;
	char buf[MAX_ERR_BUF];
	struct pending_args *mt;
	struct timespec wait;
	struct mapent *me;
	int status, state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);

	master_mutex_lock();

	debug(ap->logopt, "token %ld, name %s, request pid %u",
		(unsigned long) pkt->wait_queue_token, pkt->name, pkt->pid);

	/* Ignore packet if we're trying to shut down */
	if (ap->shutdown || ap->state == ST_SHUTDOWN_FORCE) {
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -ENOENT);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 0;
	}

	me = lookup_source_mapent(ap, pkt->name, LKP_DISTINCT);
	if (me) {
		/* Check if we recorded a mount fail for this key */
		if (me->status >= monotonic_time(NULL)) {
			ops->send_fail(ap->logopt, ap->ioctlfd,
				       pkt->wait_queue_token, -ENOENT);
			cache_unlock(me->mc);
			master_mutex_unlock();
			pthread_setcancelstate(state, NULL);
			return 0;
		}

		/* Ignore nulled indirect map entries */
		if (starts_with_null_opt(me->mapent)) {
			ops->send_fail(ap->logopt, ap->ioctlfd,
				       pkt->wait_queue_token, -ENOENT);
			cache_unlock(me->mc);
			master_mutex_unlock();
			pthread_setcancelstate(state, NULL);
			return 0;
		}
		cache_unlock(me->mc);
	}

	mt = malloc(sizeof(struct pending_args));
	if (!mt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr("malloc: %s", estr);
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -ENOMEM);
		master_mutex_unlock();
		pthread_setcancelstate(state, NULL);
		return 1;
	}
	memset(mt, 0, sizeof(struct pending_args));

	pending_cond_init(mt);

	status = pthread_mutex_init(&mt->mutex, NULL);
	if (status)
		fatal(status);

	pending_mutex_lock(mt);

	mt->ap = ap;
	strncpy(mt->name, pkt->name, pkt->len);
	mt->name[pkt->len] = '\0';
	mt->len = pkt->len;
	mt->dev = pkt->dev;
	mt->uid = pkt->uid;
	mt->gid = pkt->gid;
	mt->pid = pkt->pid;
	mt->wait_queue_token = pkt->wait_queue_token;

	status = pthread_create(&thid, &th_attr_detached, do_mount_indirect, mt);
	if (status) {
		error(ap->logopt, "expire thread create failed");
		ops->send_fail(ap->logopt,
			       ap->ioctlfd, pkt->wait_queue_token, -status);
		master_mutex_unlock();
		pending_mutex_unlock(mt);
		pending_cond_destroy(mt);
		pending_mutex_destroy(mt);
		free_pending_args(mt);
		pthread_setcancelstate(state, NULL);
		return 1;
	}

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

