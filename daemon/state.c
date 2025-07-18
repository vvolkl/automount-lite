/* ----------------------------------------------------------------------- *
 *
 *  state.c - state machine functions.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <sys/ioctl.h>

#include "automount.h"

/* Attribute to create detached thread */
extern pthread_attr_t th_attr_detached;

struct state_queue {
	pthread_t thid;
	struct list_head list;
	struct list_head pending;
	struct autofs_point *ap;
	enum states state;
	unsigned int busy;
	unsigned int done;
	unsigned int cancel;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static unsigned int signaled = 0;
static LIST_HEAD(state_queue);

static void st_set_thid(struct autofs_point *, pthread_t);
static void st_set_done(struct autofs_point *ap);

void st_mutex_lock(void)
{
	int status = pthread_mutex_lock(&mutex);
	if (status)
		fatal(status);
}

void st_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&mutex);
	if (status)
		fatal(status);
}

/*
 * Handle expire thread cleanup and return the next state the system
 * should enter as a result.
 */
void expire_cleanup(void *arg)
{
	struct ioctl_ops *ops = get_ioctl_ops();
	pthread_t thid = pthread_self();
	struct expire_args *ec;
	struct autofs_point *ap;
	int success;
	enum states next = ST_INVAL;

	ec = (struct expire_args *) arg;
	ap = ec->ap;
	success = ec->status;

	st_mutex_lock();

	debug(ap->logopt,
	      "got thid %lu path %s stat %d",
	      (unsigned long) thid, ap->path, success);

	/* Check to see if expire process finished */
	if (thid == ap->exp_thread) {
		unsigned int idle;
		int rv;

		ap->exp_thread = 0;

		switch (ap->state) {
		case ST_EXPIRE:
			/* FALLTHROUGH */
		case ST_PRUNE:
			/*
			 * If we're a submount and we've just pruned or
			 * expired everything away, try to shut down.
			 */
			if (ap->submount && !success) {
				rv = ops->askumount(ap->logopt, ap->ioctlfd, &idle);
				if (!rv && idle) {
					next = ST_SHUTDOWN_PENDING;
					break;
				}
			}

			if (ap->state == ST_EXPIRE)
				conditional_alarm_add(ap, ap->exp_runfreq);

			/* FALLTHROUGH */

		case ST_READY:
			next = ST_READY;
			break;

		case ST_SHUTDOWN_PENDING:
			/*
			 * If we reveive a mount request while trying to
			 * shutdown return to ready state unless we have
			 * been signaled to shutdown.
			 */
			rv = ops->askumount(ap->logopt, ap->ioctlfd, &idle);
			if (!rv && !idle && !ap->shutdown) {
				next = ST_READY;
				conditional_alarm_add(ap, ap->exp_runfreq);
				break;
			}

			next = ST_SHUTDOWN;
#ifdef ENABLE_IGNORE_BUSY_MOUNTS
			break;
#else
			if (success == 0)
				break;

			/* Failed shutdown returns to ready */
			warn(ap->logopt, "filesystem %s still busy", ap->path);
			conditional_alarm_add(ap, ap->exp_runfreq);
			next = ST_READY;
			break;
#endif

		case ST_SHUTDOWN_FORCE:
			next = ST_SHUTDOWN;
			break;

		default:
			error(ap->logopt, "bad state %d", ap->state);
		}

		if (next != ST_INVAL) {
			debug(ap->logopt,
			  "sigchld: exp %lu finished, switching from %d to %d",
			  (unsigned long) thid, ap->state, next);
		}
	}

	st_set_done(ap);

	if (next != ST_INVAL)
		__st_add_task(ap, next);

	st_mutex_unlock();

	return;
}

static unsigned int st_ready(struct autofs_point *ap)
{
	debug(ap->logopt,
	      "st_ready(): state = %d path %s", ap->state, ap->path);

	ap->shutdown = 0;
	ap->state = ST_READY;

	return 1;
}

enum expire {
	EXP_ERROR,
	EXP_STARTED,
	EXP_PARTIAL
};

/*
 * Generate expiry messages.  If "now" is true, timeouts are ignored.
 *
 * Returns: ERROR	- error
 *          STARTED	- expiry process started
 *          DONE	- nothing to expire
 *          PARTIAL	- partial expire
 */

void expire_proc_cleanup(void *arg)
{
	struct expire_args *ea;
	int status;

	ea = (struct expire_args *) arg;

	status = pthread_mutex_unlock(&ea->mutex);
	if (status)
		fatal(status);

	status = pthread_cond_destroy(&ea->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&ea->mutex);
	if (status)
		fatal(status);

	free(ea);

	return;
}

static enum expire expire_proc(struct autofs_point *ap, int how)
{
	pthread_t thid;
	struct expire_args *ea;
	void *(*expire)(void *);
	int status;

	assert(ap->exp_thread == 0);

	ea = malloc(sizeof(struct expire_args));
	if (!ea) {
		error(ap->logopt, "failed to malloc expire cond struct");
		return EXP_ERROR;
	}

	status = pthread_mutex_init(&ea->mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_cond_init(&ea->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&ea->mutex);
	if (status)
		fatal(status);

	ea->ap = ap;
	ea->how = how;
	ea->status = 1;

	if (ap->type == LKP_INDIRECT)
		expire = expire_proc_indirect;
	else
		expire = expire_proc_direct;

	status = pthread_create(&thid, &th_attr_detached, expire, ea);
	if (status) {
		error(ap->logopt,
		      "expire thread create for %s failed", ap->path);
		expire_proc_cleanup((void *) ea);
		return EXP_ERROR;
	}
	ap->exp_thread = thid;
	st_set_thid(ap, thid);

	pthread_cleanup_push(expire_proc_cleanup, ea);

	debug(ap->logopt, "exp_proc = %lu path %s",
		(unsigned long) ap->exp_thread, ap->path);

	ea->signaled = 0;
	while (!ea->signaled) {
		status = pthread_cond_wait(&ea->cond, &ea->mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return EXP_STARTED;
}

static void do_readmap_cleanup(void *arg)
{
	struct readmap_args *ra;
	struct autofs_point *ap;

	ra = (struct readmap_args *) arg;

	ap = ra->ap;

	st_mutex_lock();
	ap->readmap_thread = 0;
	st_set_done(ap);
	st_ready(ap);
	st_mutex_unlock();

	free(ra);

	return;
}

static int do_readmap_mount(struct autofs_point *ap,
			     struct map_source *map, struct mapent *me, time_t now)
{
	struct mapent_cache *nc;
	struct mapent *ne, *nested, *valid;
	int ret = 0;

	nc = ap->entry->master->nc;

	cache_writelock(nc);
	ne = cache_lookup_distinct(nc, me->key);
	if (ne)
		cache_unlock(nc);
	else {
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
	}

	if (me->age < now || (ne && map->master_line > ne->age)) {
		/*
		 * The map instance may have changed, such as the map name or
		 * the mount options, but the direct map entry may still exist
		 * in one of the other maps. If so then update the new cache
		 * entry device and inode so we can find it at lookup. Later,
		 * the mount for the new cache entry will just update the
		 * timeout.
		 *
		 * TODO: how do we recognise these orphaned map instances. We
		 * can't just delete these instances when the cache becomes
		 * empty because that is a valid state for a master map entry.
		 * This is becuase of the requirement to continue running with
		 * an empty cache awaiting a map re-load.
		 */
		valid = lookup_source_valid_mapent(ap, me->key, LKP_DISTINCT);
		if (valid && valid->mc == me->mc) {
			/*
			 * We've found a map entry that has been removed from
			 * the current cache so there is no need to update it.
			 * The stale entry will be dealt with when we prune the
			 * cache later.
			 */
			cache_unlock(valid->mc);
			valid = NULL;
		}
		if (valid) {
			struct mapent_cache *vmc = valid->mc;
			struct ioctl_ops *ops = get_ioctl_ops();
			time_t timeout;
			time_t runfreq;

			cache_unlock(vmc);
			debug(ap->logopt,
			     "updating cache entry for valid direct trigger %s",
			     me->key);
			cache_writelock(vmc);
			valid = cache_lookup_distinct(vmc, me->key);
			if (!valid) {
				cache_unlock(vmc);
				error(ap->logopt,
				     "failed to find expected existing valid map entry");
				return ret;
			}
			/* Take over the mount if there is one */
			valid->ioctlfd = me->ioctlfd;
			me->ioctlfd = -1;
			/* Set device and inode number of the new mapent */
			cache_set_ino_index(vmc, me);
			cache_unlock(vmc);
			/* Set timeout and calculate the expire run frequency */
			timeout = get_exp_timeout(ap, map);
			ops->timeout(ap->logopt, valid->ioctlfd, NULL, timeout);
			if (timeout) {
				runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;
				if (ap->exp_runfreq)
					ap->exp_runfreq = min(ap->exp_runfreq, runfreq);
				else
					ap->exp_runfreq = runfreq;
			}
		} else if (!is_mounted(me->key, MNTS_REAL))
			ret = do_umount_autofs_direct(ap, me);
		else
			debug(ap->logopt,
			      "%s is mounted", me->key);
	} else
		do_mount_autofs_direct(ap, me, get_exp_timeout(ap, map));

	return ret;
}

static void *do_readmap(void *arg)
{
	struct autofs_point *ap;
	struct map_source *map;
	struct mapent_cache *mc;
	struct readmap_args *ra;
	int status;
	time_t now;

	ra = (struct readmap_args *) arg;

	status = pthread_mutex_lock(&ra->mutex);
	if (status)
		fatal(status);

	ap = ra->ap;
	now = ra->now;

	ra->signaled = 1;
	status = pthread_cond_signal(&ra->cond);
	if (status) {
		error(ap->logopt, "failed to signal expire condition");
		pthread_mutex_unlock(&ra->mutex);
		fatal(status);
	}

	status = pthread_mutex_unlock(&ra->mutex);
	if (status)
		fatal(status);

	pthread_cleanup_push(do_readmap_cleanup, ra);

	info(ap->logopt, "re-reading map for %s", ap->path);

	status = lookup_nss_read_map(ap, NULL, now);
	if (!status)
		pthread_exit(NULL);

	if (ap->type == LKP_INDIRECT) {
		struct ioctl_ops *ops = get_ioctl_ops();
		time_t timeout = get_exp_timeout(ap, ap->entry->maps);
		ap->exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;
		ops->timeout(ap->logopt, ap->ioctlfd, NULL, timeout);
		lookup_prune_cache(ap, now);
		status = lookup_ghost(ap);
	} else {
		struct mapent *me;
		unsigned int append_alarm = !ap->exp_runfreq;

		master_source_readlock(ap->entry);
		pthread_cleanup_push(master_source_lock_cleanup, ap->entry);
		map = ap->entry->maps;
		while (map) {
			/* Is map source up to date or no longer valid */
			if (!map->stale && !check_stale_instances(map)) {
				map = map->next;
				continue;
			}
			mc = map->mc;
			pthread_cleanup_push(cache_lock_cleanup, mc);
			cache_readlock(mc);
restart:
			me = cache_enumerate(mc, NULL);
			while (me) {
				int ret = do_readmap_mount(ap, map, me, now);
				if (ret == -1)
					goto restart;
				me = cache_enumerate(mc, me);
			}
			lookup_prune_one_cache(ap, map->mc, now);
			pthread_cleanup_pop(1);
			clear_stale_instances(map);
			map->stale = 0;
			map = map->next;
		}

		/* If the direct mount map was empty at startup no expire
		 * alarm will have been added. So add it here if there are
		 * now map entries.
		 */
		if (append_alarm && ap->exp_runfreq) {
			time_t seconds = ap->exp_runfreq + rand() % ap->exp_runfreq;
			conditional_alarm_add(ap, seconds);
		}

		pthread_cleanup_pop(1);
	}

	pthread_cleanup_pop(1);

	return NULL;
}

static void st_readmap_cleanup(void *arg)
{
	struct readmap_args *ra;
	int status;

	ra = (struct readmap_args *) arg;

	status = pthread_mutex_unlock(&ra->mutex);
	if (status)
		fatal(status);

	status = pthread_cond_destroy(&ra->cond);
	if (status)
		fatal(status);

	status = pthread_mutex_destroy(&ra->mutex);
	if (status)
		fatal(status);

	return;
}

static unsigned int st_readmap(struct autofs_point *ap)
{
	pthread_t thid;
	struct readmap_args *ra;
	int status;
	int now = monotonic_time(NULL);

	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	assert(ap->readmap_thread == 0);

	ap->state = ST_READMAP;

	ra = malloc(sizeof(struct readmap_args));
	if (!ra) {
		error(ap->logopt, "failed to malloc readmap cond struct");
		/* It didn't work: return to ready */
		st_ready(ap);
		conditional_alarm_add(ap, ap->exp_runfreq);
		return 0;
	}

	status = pthread_mutex_init(&ra->mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_cond_init(&ra->cond, NULL);
	if (status)
		fatal(status);

	status = pthread_mutex_lock(&ra->mutex);
	if (status)
		fatal(status);

	ra->ap = ap;
	ra->now = now;

	status = pthread_create(&thid, &th_attr_detached, do_readmap, ra);
	if (status) {
		error(ap->logopt, "readmap thread create failed");
		st_readmap_cleanup(ra);
		free(ra);
		/* It didn't work: return to ready */
		st_ready(ap);
		conditional_alarm_add(ap, ap->exp_runfreq);
		return 0;
	}
	ap->readmap_thread = thid;
	st_set_thid(ap, thid);

	pthread_cleanup_push(st_readmap_cleanup, ra);

	ra->signaled = 0;
	while (!ra->signaled) {
		status = pthread_cond_wait(&ra->cond, &ra->mutex);
		if (status)
			fatal(status);
	}

	pthread_cleanup_pop(1);

	return 1;
}

static unsigned int st_prepare_shutdown(struct autofs_point *ap)
{
	int exp;

	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY || ap->state == ST_EXPIRE);
	ap->state = ST_SHUTDOWN_PENDING;

	/* Unmount everything */
	exp = expire_proc(ap, AUTOFS_EXP_IMMEDIATE);
	switch (exp) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		/* It didn't work: return to ready */
		conditional_alarm_add(ap, ap->exp_runfreq);
		st_ready(ap);
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_force_shutdown(struct autofs_point *ap)
{
	int exp;

	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY || ap->state == ST_EXPIRE);
	ap->state = ST_SHUTDOWN_FORCE;

	/* Unmount everything */
	exp = expire_proc(ap, AUTOFS_EXP_FORCE | AUTOFS_EXP_IMMEDIATE);
	switch (exp) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		/* It didn't work: return to ready */
		conditional_alarm_add(ap, ap->exp_runfreq);
		st_ready(ap);
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_shutdown(struct autofs_point *ap)
{
	int ret;

	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_SHUTDOWN_PENDING || ap->state == ST_SHUTDOWN_FORCE);

	ap->state = ST_SHUTDOWN;
	ret = pthread_kill(ap->thid, SIGCONT);
	if (ret)
		error(LOGOPT_ANY, "error %d sending shutdown signal", ret);

	return 0;
}

static unsigned int st_prune(struct autofs_point *ap)
{
	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_PRUNE;

	switch (expire_proc(ap, AUTOFS_EXP_IMMEDIATE)) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		conditional_alarm_add(ap, ap->exp_runfreq);
		st_ready(ap);
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static unsigned int st_expire(struct autofs_point *ap)
{
	debug(ap->logopt, "state %d path %s", ap->state, ap->path);

	assert(ap->state == ST_READY);
	ap->state = ST_EXPIRE;

	switch (expire_proc(ap, AUTOFS_EXP_NORMAL)) {
	case EXP_ERROR:
	case EXP_PARTIAL:
		conditional_alarm_add(ap, ap->exp_runfreq);
		st_ready(ap);
		return 0;

	case EXP_STARTED:
		return 1;
	}
	return 0;
}

static struct state_queue *st_alloc_task(struct autofs_point *ap, enum states state)
{
	struct state_queue *task;

	task = malloc(sizeof(struct state_queue));
	if (!task)
		return NULL;
	memset(task, 0, sizeof(struct state_queue));

	task->ap = ap;
	task->state = state;

	INIT_LIST_HEAD(&task->list);
	INIT_LIST_HEAD(&task->pending);

	return task;
}

/*
 * Insert alarm entry on ordered list.
 * State queue mutex and ap state mutex, in that order, must be held.
 */
int __st_add_task(struct autofs_point *ap, enum states state)
{
	struct list_head *head;
	struct list_head *p, *q;
	struct state_queue *new;
	unsigned int empty = 1;
	int status;

	/* Task termination marker, poke state machine */
	if (state == ST_READY) {
		st_ready(ap);

		signaled = 1;
		status = pthread_cond_signal(&cond);
		if (status)
			fatal(status);

		return 1;
	}

	if (ap->state == ST_SHUTDOWN)
		return 1;

	if (state == ST_SHUTDOWN)
		return st_shutdown(ap);

	head = &state_queue;

	/* Add to task queue for autofs_point ? */
	list_for_each(p, head) {
		struct state_queue *task;

		task = list_entry(p, struct state_queue, list);

		if (task->ap != ap)
			continue;

		empty = 0;

		/* Don't add duplicate tasks */
		if ((task->state == state && !task->done) ||
		   (ap->state == ST_SHUTDOWN_PENDING ||
		    ap->state == ST_SHUTDOWN_FORCE))
			break;

		/* No pending tasks */
		if (list_empty(&task->pending)) {
			new = st_alloc_task(ap, state);
			if (new)
				list_add_tail(&new->pending, &task->pending);
			goto done;
		}

		list_for_each(q, &task->pending) {
			struct state_queue *p_task;

			p_task = list_entry(q, struct state_queue, pending);

			if (p_task->state == state ||
			   (ap->state == ST_SHUTDOWN_PENDING ||
			    ap->state == ST_SHUTDOWN_FORCE))
				goto done;
		}

		new = st_alloc_task(ap, state);
		if (new)
			list_add_tail(&new->pending, &task->pending);
done:
		break;
	}

	if (empty) {
		new = st_alloc_task(ap, state);
		if (new)
			list_add(&new->list, head);
	}

	signaled = 1;
	status = pthread_cond_signal(&cond);
	if (status)
		fatal(status);

	return 1;
}

int st_add_task(struct autofs_point *ap, enum states state)
{
	int ret;

	st_mutex_lock();
	ret = __st_add_task(ap, state);
	st_mutex_unlock();

	return ret;
}

/*
 * Remove state queue tasks for ap.
 * State queue mutex and ap state mutex, in that order, must be held.
 */
void st_remove_tasks(struct autofs_point *ap)
{
	struct list_head *head;
	struct list_head *p, *q;
	struct state_queue *task, *waiting;
	int status;

	st_mutex_lock();

	head = &state_queue;

	if (list_empty(head)) {
		st_mutex_unlock();
		return;
	}

	p = head->next;
	while (p != head) {
		task = list_entry(p, struct state_queue, list);
		p = p->next;

		if (task->ap != ap)
			continue;

		if (task->busy) {
			/* We only cancel readmap, prune and expire */
			if (task->state == ST_EXPIRE ||
			    task->state == ST_PRUNE ||
			    task->state == ST_READMAP)
				task->cancel = 1;
		}

		q = (&task->pending)->next;
		while(q != &task->pending) {
			waiting = list_entry(q, struct state_queue, pending);
			q = q->next;

			/* Don't remove existing shutdown task */
			if (waiting->state != ST_SHUTDOWN_PENDING &&
			    waiting->state != ST_SHUTDOWN_FORCE) {
				list_del(&waiting->pending);
				free(waiting);
			}
		}
	}

	signaled = 1;
	status = pthread_cond_signal(&cond);
	if (status)
		fatal(status);

	st_mutex_unlock();

	return;
}

static int st_task_active(struct autofs_point *ap, enum states state)
{
	struct list_head *head;
	struct list_head *p, *q;
	struct state_queue *task, *waiting;
	unsigned int active = 0;

	st_mutex_lock();

	head = &state_queue;

	list_for_each(p, head) {
		task = list_entry(p, struct state_queue, list);

		if (task->ap != ap)
			continue;

		if (task->state == state) {
			active = 1;
			break;
		}

		if (state == ST_ANY) {
			active = 1;
			break;
		}

		list_for_each(q, &task->pending) {
			waiting = list_entry(q, struct state_queue, pending);

			if (waiting->state == state) {
				active = 1;
				break;
			}

			if (state == ST_ANY) {
				active = 1;
				break;
			}
		}
	}

	st_mutex_unlock();

	return active;
}

int st_wait_task(struct autofs_point *ap, enum states state, unsigned int seconds)
{
	unsigned int wait = 0;
	unsigned int duration = 0;
	int ret = 0;

	while (1) {
		struct timespec t = { 0, 200000000 };
		struct timespec r;

		while (nanosleep(&t, &r) == -1 && errno == EINTR)
			memcpy(&t, &r, sizeof(struct timespec));

		if (wait++ == 4) {
			wait = 0;
			duration++;
		}

		if (!st_task_active(ap, state)) {
			ret = 1;
			break;
		}

		if (seconds && duration >= seconds)
			break;
	}

	return ret;
}

int st_wait_state(struct autofs_point *ap, enum states state)
{
	while (1) {
		struct timespec t = { 0, 200000000 };
		struct timespec r;

		while (nanosleep(&t, &r) == -1 && errno == EINTR)
			memcpy(&t, &r, sizeof(struct timespec));

		st_mutex_lock();
		if (ap->state == state) {
			st_mutex_unlock();
			return 1;
		}
		st_mutex_unlock();
	}

	return 0;
}


static int run_state_task(struct state_queue *task)
{
	struct autofs_point *ap;
	enum states next_state, state;
	unsigned long ret = 0;
 
	ap = task->ap;
	next_state = task->state;

	state = ap->state;

	if (next_state != state) {
		switch (next_state) {
		case ST_PRUNE:
			ret = st_prune(ap);
			break;

		case ST_EXPIRE:
			ret = st_expire(ap);
			break;

		case ST_READMAP:
			ret = st_readmap(ap);
			break;

		case ST_SHUTDOWN_PENDING:
			ret = st_prepare_shutdown(ap);
			break;

		case ST_SHUTDOWN_FORCE:
			ret = st_force_shutdown(ap);
			break;

		default:
			error(ap->logopt, "bad next state %d", next_state);
		}
	}

	return ret;
}

static void st_set_thid(struct autofs_point *ap, pthread_t thid)
{
	struct list_head *p, *head = &state_queue;
	struct state_queue *task;

	list_for_each(p, head) {
		task = list_entry(p, struct state_queue, list);
		if (task->ap == ap) {
			task->thid = thid;
			break;
		}
	}
	return;
}

/* Requires state mutex to be held */
static void st_set_done(struct autofs_point *ap)
{
	struct list_head *p, *head;
	struct state_queue *task;

	head = &state_queue;
	list_for_each(p, head) {
		task = list_entry(p, struct state_queue, list);
		if (task->ap == ap) {
			task->done = 1;
			break;
		}
	}

	return;
}

static void *st_queue_handler(void *arg)
{
	struct list_head *head;
	struct list_head *p;
	int status, ret;

	st_mutex_lock();

	while (1) {
		/*
		 * If the state queue list is empty, wait until an
		 * entry is added.
		 */
		head = &state_queue;

		while (list_empty(head)) {
			status = pthread_cond_wait(&cond, &mutex);
			if (status)
				fatal(status);
		}

		p = head->next;
		while(p != head) {
			struct state_queue *task;

			task = list_entry(p, struct state_queue, list);
			p = p->next;

			if (task->cancel) {
				list_del(&task->list);
				free(task);
				continue;
			}

			task->busy = 1;

			ret = run_state_task(task);
			if (!ret) {
				list_del(&task->list);
				free(task);
			}
		}

		while (1) {
			signaled = 0;
			while (!signaled) {
				status = pthread_cond_wait(&cond, &mutex);
				if (status)
					fatal(status);
			}

			head = &state_queue;
			p = head->next;
			while (p != head) {
				struct state_queue *task, *next;

				task = list_entry(p, struct state_queue, list);
				p = p->next;

				/* Task may have been canceled before it started */
				if (!task->thid && task->cancel)
					goto remove;

				if (!task->busy) {
					/* Start a new task */
					task->busy = 1;

					ret = run_state_task(task);
					if (!ret)
						goto remove;
					continue;
				}

				/* Still starting up */
				if (!task->thid)
					continue;

				if (task->cancel) {
					pthread_cancel(task->thid);
					task->cancel = 0;
					continue;
				}

				/* Still busy */
				if (!task->done)
					continue;

remove:
				/* No more tasks for this queue */
				if (list_empty(&task->pending)) {
					list_del(&task->list);
					free(task);
					continue;
				}

				/* Next task */
				next = list_entry((&task->pending)->next,
							struct state_queue, pending);

				list_del(&task->list);
				list_del_init(&next->pending);
				free(task);

				list_add_tail(&next->list, head);
				if (p == head)
					p = head->next;
			}

			if (list_empty(head))
				break;
		}
	}
}

int st_start_handler(void)
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

	status = pthread_create(&thid, pattrs, st_queue_handler, NULL);

	if (pattrs)
		pthread_attr_destroy(pattrs);

	return !status;
}

