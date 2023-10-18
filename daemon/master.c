/* ----------------------------------------------------------------------- *
 *   
 *  master.c - master map utility routines.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net>
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

#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include "automount.h"

/* The root of the map entry tree */
struct master *master_list = NULL;

extern const char *global_options;
extern long global_negative_timeout;
extern long global_positive_timeout;

/* Attribute to create a joinable thread */
extern pthread_attr_t th_attr;

extern struct startup_cond suc;

static struct map_source *
__master_find_map_source(struct master_mapent *,
			 const char *, const char *, int, const char **);

static pthread_mutex_t master_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t instance_mutex = PTHREAD_MUTEX_INITIALIZER;

void master_mutex_lock(void)
{
	int status = pthread_mutex_lock(&master_mutex);
	if (status)
		fatal(status);
}

void master_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&master_mutex);
	if (status)
		fatal(status);
}

void master_mutex_lock_cleanup(void *arg)
{
	master_mutex_unlock();
	return;
}

void map_module_writelock(struct map_source *map)
{
	int status = pthread_rwlock_wrlock(&map->module_lock);
	if (status)
		fatal(status);
}

int map_module_try_writelock(struct map_source *map)
{
	int status = pthread_rwlock_trywrlock(&map->module_lock);
	if (status && status != EBUSY && status != EDEADLK)
		fatal(status);
	return status;
}

void map_module_readlock(struct map_source *map)
{
	int status = pthread_rwlock_rdlock(&map->module_lock);
	if (status)
		fatal(status);
}

void map_module_unlock(struct map_source *map)
{
	int status = pthread_rwlock_unlock(&map->module_lock);
	if (status)
		fatal(status);
}

void map_module_lock_cleanup(void *arg)
{
	struct map_source *map = (struct map_source *) arg;

	map_module_unlock(map);
}

int master_add_autofs_point(struct master_mapent *entry, unsigned logopt,
			    unsigned nobind, unsigned ghost, int submount)
{
	struct autofs_point *ap;

	ap = malloc(sizeof(struct autofs_point));
	if (!ap)
		return 0;

	ap->state = ST_INIT;

	ap->path = strdup(entry->path);
	if (!ap->path) {
		free(ap);
		return 0;
	}
	ap->len = strlen(ap->path);
	ap->pref = NULL;

	ap->entry = entry;
	ap->exp_thread = 0;
	ap->readmap_thread = 0;
	/*
	 * Program command line option overrides config.
	 * We can't use 0 negative timeout so use default.
	 * We can't use <0 positive timeout so use default.
	 */
	if (global_negative_timeout <= 0)
		ap->negative_timeout = defaults_get_negative_timeout();
	else
		ap->negative_timeout = global_negative_timeout;
	if (global_positive_timeout < 0)
		ap->positive_timeout = defaults_get_positive_timeout();
	else
		ap->positive_timeout = global_positive_timeout;
	ap->exp_timeout = defaults_get_timeout();
	ap->exp_runfreq = 0;
	ap->flags = 0;

	if (defaults_get_use_ignore_mount_option())
		ap->flags = MOUNT_FLAG_IGNORE;
	if (ghost)
		ap->flags |= MOUNT_FLAG_GHOST;

	if (nobind)
		ap->flags |= MOUNT_FLAG_NOBIND;

	if (ap->path[1] == '-')
		ap->type = LKP_DIRECT;
	else
		ap->type = LKP_INDIRECT;

	ap->logopt = logopt;

	ap->parent = NULL;
	ap->thid = 0;
	ap->submount = submount;
	INIT_LIST_HEAD(&ap->mounts);
	INIT_LIST_HEAD(&ap->submounts);
	INIT_LIST_HEAD(&ap->amdmounts);
	ap->shutdown = 0;

	ap->mode = 0;

	entry->ap = ap;

	return 1;
}

void master_free_autofs_point(struct autofs_point *ap)
{
	if (!ap)
		return;

	mnts_remove_amdmounts(ap);

	if (ap->pref)
		free(ap->pref);
	free(ap->path);
	free(ap);
}

struct map_source *
master_add_map_source(struct master_mapent *entry,
		      char *type, char *format, time_t age,
		      int argc, const char **argv)
{
	struct map_source *source;
	char *ntype, *nformat;
	const char **tmpargv;
	int status;

	source = malloc(sizeof(struct map_source));
	if (!source)
		return NULL;
	memset(source, 0, sizeof(struct map_source));
	source->ref = 1;

	if (type) {
		ntype = strdup(type);
		if (!ntype) {
			master_free_map_source(source, 0);
			return NULL;
		}
		source->type = ntype;
	}

	if (format) {
		nformat = strdup(format);
		if (!nformat) {
			master_free_map_source(source, 0);
			return NULL;
		}
		source->format = nformat;
		if (!strcmp(nformat, "amd"))
			source->flags |= MAP_FLAG_FORMAT_AMD;
	}

	source->age = age;
	source->stale = 1;

	tmpargv = copy_argv(argc, argv);
	if (!tmpargv) {
		master_free_map_source(source, 0);
		return NULL;
	}
	source->argc = argc;
	source->argv = tmpargv;
	if (source->argv[0])
		source->name = strdup(source->argv[0]);

	master_source_writelock(entry);

	if (!entry->maps) {
		source->mc = cache_init(entry->ap, source);
		if (!source->mc) {
			master_free_map_source(source, 0);
			master_source_unlock(entry);
			return NULL;
		}
		entry->maps = source;
	} else {
		struct map_source *this, *last, *next;

		/* Typically there only a few map sources */

		this = __master_find_map_source(entry, type, format, argc, tmpargv);
		if (this) {
			debug(entry->ap->logopt,
			      "map source used without taking reference");
			this->age = age;
			master_free_map_source(source, 0);
			master_source_unlock(entry);
			return this;
		}

		source->mc = cache_init(entry->ap, source);
		if (!source->mc) {
			master_free_map_source(source, 0);
			master_source_unlock(entry);
			return NULL;
		}

		last = NULL;
		next = entry->maps;
		while (next) {
			last = next;
			next = next->next;
		}
		if (last)
			last->next = source;
		else
			entry->maps = source;
	}

	master_source_unlock(entry);

	status = pthread_rwlock_init(&source->module_lock, NULL);
	if (status)
		fatal(status);

	return source;
}

static int compare_source_type_and_format(struct map_source *map, const char *type, const char *format)
{
	int res = 0;

	if (type) {
		if (!map->type)
			goto done;

		if (strcmp(map->type, type))
			goto done;
	} else if (map->type)
		goto done;

	if (format) {
		if (!map->format)
			goto done;

		if (strcmp(map->format, format))
			goto done;
	} else if (map->format)
		goto done;

	res = 1;
done:
	return res;
}

static struct map_source *
__master_find_map_source(struct master_mapent *entry,
			 const char *type, const char *format,
			 int argc, const char **argv)
{
	struct map_source *map;
	struct map_source *source = NULL;
	int res;

	map = entry->maps;
	while (map) {
		res = compare_source_type_and_format(map, type, format);
		if (!res)
			goto next;

		res = compare_argv(map->argc, map->argv, argc, argv);
		if (!res)
			goto next;

		source = map;
		break;
next:
		map = map->next;
	}

	return source;
}

struct map_source *master_find_map_source(struct master_mapent *entry,
				const char *type, const char *format,
				int argc, const char **argv)
{
	struct map_source *source = NULL;

	master_source_readlock(entry);
	source = __master_find_map_source(entry, type, format, argc, argv);
	master_source_unlock(entry);

	return source;
}

struct map_source *
master_get_map_source(struct master_mapent *entry,
		      const char *type, const char *format,
		      int argc, const char **argv)
{
	struct map_source *source = NULL;

	master_source_readlock(entry);
	source = __master_find_map_source(entry, type, format, argc, argv);
	if (source)
		source->ref++;
	master_source_unlock(entry);

	return source;
}

static void __master_free_map_source(struct map_source *source, unsigned int free_cache)
{
	int status;

	/* instance map sources are not ref counted */
	if (source->ref && --source->ref)
		return;
	if (source->type)
		free(source->type);
	if (source->format)
		free(source->format);
	if (source->name)
		free(source->name);
	if (free_cache && source->mc)
		cache_release(source);
	if (source->lookup) {
		struct map_source *instance;

		instance = source->instance;
		while (instance) {
			if (instance->lookup) {
				close_lookup(instance->lookup);
				instance->lookup = NULL;
			}
			instance = instance->next;
		}
		close_lookup(source->lookup);
		source->lookup = NULL;
	}
	if (source->argv)
		free_argv(source->argc, source->argv);
	if (source->instance) {
		struct map_source *instance, *next;

		instance = source->instance;
		while (instance) {
			next = instance->next;
			__master_free_map_source(instance, 0);
			instance = next;
		}
		source->instance = NULL;
	}

	status = pthread_rwlock_destroy(&source->module_lock);
	if (status)
		fatal(status);

	free(source);

	return;
}

void master_free_map_source(struct map_source *source, unsigned int free_cache)
{
	int status;

	status = pthread_mutex_lock(&instance_mutex);
	if (status)
		fatal(status);

	__master_free_map_source(source, free_cache);

	status = pthread_mutex_unlock(&instance_mutex);
	if (status)
		fatal(status);
}

struct map_source *master_find_source_instance(struct map_source *source, const char *type, const char *format, int argc, const char **argv)
{
	struct map_source *map;
	struct map_source *instance = NULL;
	int status, res;

	status = pthread_mutex_lock(&instance_mutex);
	if (status)
		fatal(status);

	map = source->instance;
	while (map) {
		res = compare_source_type_and_format(map, type, format);
		if (!res)
			goto next;

		if (!argv) {
			instance = map;
			break;
		}

		res = compare_argv(map->argc, map->argv, argc, argv);
		if (!res)
			goto next;

		instance = map;
		break;
next:
		map = map->next;
	}

	status = pthread_mutex_unlock(&instance_mutex);
	if (status)
		fatal(status);

	return instance;
}

struct map_source *
master_add_source_instance(struct map_source *source, const char *type, const char *format, time_t age, int argc, const char **argv)
{
	struct map_source *instance;
	struct map_source *new;
	char *ntype, *nformat;
	const char **tmpargv;
	int status;

	instance = master_find_source_instance(source, type, format, argc, argv);
	if (instance)
		return instance;

	new = malloc(sizeof(struct map_source));
	if (!new)
		return NULL;
	memset(new, 0, sizeof(struct map_source));

	if (type) {
		ntype = strdup(type);
		if (!ntype) {
			master_free_map_source(new, 0);
			return NULL;
		}
		new->type = ntype;
	}

	if (format) {
		nformat = strdup(format);
		if (!nformat) {
			master_free_map_source(new, 0);
			return NULL;
		}
		new->format = nformat;
		if (!strcmp(nformat, "amd"))
			new->flags |= MAP_FLAG_FORMAT_AMD;
	}

	new->age = age;
	new->master_line = 0;
	new->mc = source->mc;
	new->exp_timeout = source->exp_timeout;
	new->stale = 1;

	tmpargv = copy_argv(argc, argv);
	if (!tmpargv) {
		master_free_map_source(new, 0);
		return NULL;
	}
	new->argc = argc;
	new->argv = tmpargv;
	if (source->name)
		new->name = strdup(source->name);

	status = pthread_mutex_lock(&instance_mutex);
	if (status)
		fatal(status);

	if (!source->instance)
		source->instance = new;
	else {
		/*
		 * We know there's no other instance of this
		 * type so just add to head of list
		 */
		new->next = source->instance;
		source->instance = new;
	}

	status = pthread_mutex_unlock(&instance_mutex);
	if (status)
		fatal(status);

	status = pthread_rwlock_init(&new->module_lock, NULL);
	if (status)
		fatal(status);

	return new;
}

int check_stale_instances(struct map_source *source)
{
	struct map_source *map;

	if (!source)
		return 0;

	map = source->instance;
	while (map) {
		if (map->stale)
			return 1;
		if (check_stale_instances(map))
			return 1;
		map = map->next;
	}

	return 0;
}

void clear_stale_instances(struct map_source *source)
{
	struct map_source *map;

	if (!source)
		return;

	map = source->instance;
	while (map) {
		clear_stale_instances(map);
		if (map->stale)
			map->stale = 0;
		map = map->next;
	}

	return;
}

void send_map_update_request(struct autofs_point *ap)
{
	struct map_source *map;
	int status, need_update = 0;

	status = pthread_mutex_lock(&instance_mutex);
	if (status)
		fatal(status);

	map = ap->entry->maps;
	while (map) {
		if (check_stale_instances(map))
			map->stale = 1;
		if (map->stale) {
			need_update = 1;
			break;
		}
		map = map->next;
	}

	status = pthread_mutex_unlock(&instance_mutex);
	if (status)
		fatal(status);

	if (!need_update)
		return;

	st_add_task(ap, ST_READMAP);

	return;
}

void master_source_writelock(struct master_mapent *entry)
{
	int status;

	status = pthread_rwlock_wrlock(&entry->source_lock);
	if (status) {
		logmsg("master_mapent source write lock failed");
		fatal(status);
	}
	return;
}

void master_source_readlock(struct master_mapent *entry)
{
	int retries = 25;
	int status;

	while (retries--) {
		status = pthread_rwlock_rdlock(&entry->source_lock);
		if (status != EAGAIN && status != EBUSY)
			break;
		else {
                	struct timespec t = { 0, 200000000 };
	                struct timespec r;

			if (status == EAGAIN)
				logmsg("master_mapent source too many readers");
			else
				logmsg("master_mapent source write lock held");

                	while (nanosleep(&t, &r) == -1 && errno == EINTR)
                        	memcpy(&t, &r, sizeof(struct timespec));
		}
	}

	if (status) {
		logmsg("master_mapent source read lock failed");
		fatal(status);
	}

	return;
}

void master_source_unlock(struct master_mapent *entry)
{
	int status;

	status = pthread_rwlock_unlock(&entry->source_lock);
	if (status) {
		logmsg("master_mapent source unlock failed");
		fatal(status);
	}
	return;
}

void master_source_lock_cleanup(void *arg)
{
	struct master_mapent *entry = (struct master_mapent *) arg;

	master_source_unlock(entry);

	return;
}

struct master_mapent *master_find_mapent(struct master *master, const char *path)
{
	struct list_head *head, *p;

	head = &master->mounts;
	list_for_each(p, head) {
		struct master_mapent *entry;

		entry = list_entry(p, struct master_mapent, list);

		if (!strcmp(entry->path, path))
			return entry;
	}

	return NULL;
}

struct autofs_point *master_find_mapent_by_devid(struct master *master, dev_t devid)
{
	struct autofs_point *ap = NULL;
	struct list_head *head, *p;

	master_mutex_lock();

	head = &master->mounts;
	list_for_each(p, head) {
		struct master_mapent *entry;

		entry = list_entry(p, struct master_mapent, list);

		if (entry->ap->dev == devid) {
			ap = entry->ap;
			break;
		}

		ap = mnt_find_submount_by_devid(&entry->ap->submounts, devid);
		if (ap)
			break;
	}

	master_mutex_unlock();

	return ap;
}

static unsigned int master_partial_match_amd_mapent(struct master *master, const char *path)
{
	struct list_head *head, *p;
	size_t path_len = strlen(path);
	int ret = 0;

	head = &master->mounts;
	list_for_each(p, head) {
		struct master_mapent *entry;
		size_t entry_len;
		size_t cmp_len;

		entry = list_entry(p, struct master_mapent, list);

		entry_len = entry->len;
		cmp_len = min(entry_len, path_len);

		if (!strncmp(entry->path, path, cmp_len)) {
			/* paths are equal, matching master map entry ? */
			if (entry_len == path_len) {
				if (entry->maps &&
				    entry->maps->flags & MAP_FLAG_FORMAT_AMD)
					ret = 1;
				else
					ret = -1;
				break;
			}

			/* amd mount conflicts with entry mount */
			if (entry_len > path_len &&
			    *(entry->path + path_len) == '/') {
				ret = -1;
				break;
			}

			/* entry mount conflicts with amd mount */
			if (entry_len < path_len &&
			    *(path + entry_len) == '/') {
				ret = -1;
				break;
			}
		}
	}

	return ret;
}

struct master_mapent *master_new_mapent(struct master *master, const char *path, time_t age)
{
	struct master_mapent *entry;
	int status;
	char *tmp;

	entry = malloc(sizeof(struct master_mapent));
	if (!entry)
		return NULL;

	memset(entry, 0, sizeof(struct master_mapent));

	tmp = strdup(path);
	if (!tmp) {
		free(entry);
		return NULL;
	}
	entry->path = tmp;
	entry->len = strlen(tmp);

	entry->age = age;
	entry->master = master;
	entry->current = NULL;
	entry->maps = NULL;
	entry->ap = NULL;

	status = pthread_rwlock_init(&entry->source_lock, NULL);
	if (status)
		fatal(status);

	INIT_LIST_HEAD(&entry->list);

	return entry;
}

void master_add_mapent(struct master *master, struct master_mapent *entry)
{
	list_add_tail(&entry->list, &master->mounts);
	return;
}

void master_remove_mapent(struct master_mapent *entry)
{
	struct master *master = entry->master;
	struct autofs_point *ap = entry->ap;

	if (ap->submount) {
		struct mnt_list *mnt;

		mnt = mnts_find_submount(ap->path);
		if (mnt) {
			warn(ap->logopt,
			     "map entry %s in use at shutdown", ap->path);
			mnts_put_mount(mnt);
		}
		list_add(&entry->join, &master->completed);
		return;
	}

	if (!list_empty(&entry->list)) {
		list_del_init(&entry->list);
		list_add(&entry->join, &master->completed);
	}

	return;
}

void master_free_mapent_sources(struct master_mapent *entry, unsigned int free_cache)
{
	if (entry->maps) {
		struct map_source *m, *n;

		m = entry->maps;
		while (m) {
			n = m->next;
			master_free_map_source(m, free_cache);
			m = n;
		}
		entry->maps = NULL;
	}

	return;
}

void master_free_mapent(struct master_mapent *entry)
{
	int status;

	if (entry->path)
		free(entry->path);

	master_free_autofs_point(entry->ap);

	status = pthread_rwlock_destroy(&entry->source_lock);
	if (status)
		fatal(status);

	free(entry);

	return;
}

struct master *master_new(const char *name, unsigned int timeout, unsigned int flags)
{
	struct master *master;
	char *tmp;

	master = malloc(sizeof(struct master));
	if (!master)
		return NULL;

	if (!name)
		tmp = (char *) defaults_get_master_map();
	else
		tmp = strdup(name);

	if (!tmp) {
		free(master);
		return NULL;
	}

	master->name = tmp;
	master->nc = NULL;

	master->recurse = 0;
	master->depth = 0;
	master->reading = 0;
	master->read_fail = 0;
	master->readall = 0;
	master->default_ghost = flags & DAEMON_FLAGS_GHOST;
	master->default_timeout = timeout;
	master->default_logging = defaults_get_logging();
	master->logopt = master->default_logging;

	INIT_LIST_HEAD(&master->mounts);
	INIT_LIST_HEAD(&master->completed);

	return master;
}

static void master_update_amd_mount_section_mount(struct master *master,
						  const char *path, time_t age)
{
	unsigned int m_logopt = master->logopt;
	struct master_mapent *entry;
	struct map_source *source;
	unsigned int loglevel;
	unsigned int logopt;
	unsigned int flags;
	time_t timeout;
	char *map;
	char *opts;

	entry = master_find_mapent(master, path);
	if (!entry)
		return;

	map = conf_amd_get_map_name(path);
	if (!map)
		return;

	/* amd top level mounts have only one map */
	source = entry->maps;
	if (strcmp(source->name, map) != 0) {
		struct map_source *new;
		char *type;
		char *argv[2];

		type = conf_amd_get_map_type(path);
		argv[0] = map;
		argv[1] = NULL;

		new = master_add_map_source(entry, type, "amd",
					    age, 1, (const char **) argv);
		if (!new) {
			error(m_logopt,
			      "failed to add source for amd section mount %s",
			      path);
			if (type)
				free(type);
			goto out;
		}
		master_free_map_source(source, 0);
		entry->maps = new;
		source = new;
		if (type)
			free(type);
	}

	loglevel = conf_amd_get_log_options();
	logopt = m_logopt;
	if (loglevel <= LOG_DEBUG && loglevel > LOG_INFO)
		logopt = LOGOPT_DEBUG;
	else if (loglevel <= LOG_INFO && loglevel > LOG_ERR)
		logopt = LOGOPT_VERBOSE;

	flags = conf_amd_get_flags(path);
	if (flags & CONF_BROWSABLE_DIRS)
		entry->ap->flags |= MOUNT_FLAG_GHOST;

	opts = conf_amd_get_map_options(path);
	if (opts) {
		if (strstr(opts, "cache:=all"))
			entry->ap->flags |= MOUNT_FLAG_AMD_CACHE_ALL;
		free(opts);
	}

	entry->ap->logopt = logopt;

	timeout = conf_amd_get_dismount_interval(path);
	set_exp_timeout(entry->ap, source, timeout);
	source->master_line = 0;
	entry->age = age;
out:
	free(map);
}

static void master_add_amd_mount_section_mounts(struct master *master, time_t age)
{
	unsigned int m_logopt = master->logopt;
	struct master_mapent *entry;
	struct map_source *source;
	unsigned int loglevel;
	unsigned int logopt;
	unsigned int flags;
	char *argv[2];
	char **paths;
	int ret;
	int i;

	loglevel = conf_amd_get_log_options();

	paths = conf_amd_get_mount_paths();
	if (!paths)
		return;

	i = 0;
	while (paths[i]) {
		const char *path = paths[i];
		unsigned int ghost = 0;
		time_t timeout;
		char *type = NULL;
		char *map = NULL;
		char *opts;

		ret = master_partial_match_amd_mapent(master, path);
		if (ret) {
			/* If this amd entry is already present in the
			 * master map it's not a duplicate, don't issue
			 * an error message.
			 */
			if (ret == 1) {
				master_update_amd_mount_section_mount(master, path, age);
				goto next;
			}
			info(m_logopt,
			     "amd section mount path conflict, %s ignored",
			     path);
			goto next;
		}

		map = conf_amd_get_map_name(path);
		if (!map) {
			error(m_logopt,
			      "failed to get map name for amd section mount %s",
			      path);
			goto next;
		}

		entry = master_new_mapent(master, path, age);
		if (!entry) {
			error(m_logopt,
			      "failed to allocate new amd section mount %s",
			      path);
			goto next;
		}

		logopt = m_logopt;
		if (loglevel <= LOG_DEBUG && loglevel > LOG_INFO)
			logopt = LOGOPT_DEBUG;
		else if (loglevel <= LOG_INFO && loglevel > LOG_ERR)
			logopt = LOGOPT_VERBOSE;

		/* It isn't possible to provide the fullybrowsable amd
		 * browsing functionality within the autofs framework.
		 * This flag will not be set if browsable_dirs = full
		 * in the configuration or fullybrowsable is present as
		 * an option.
		 */
		flags = conf_amd_get_flags(path);
		if (flags & CONF_BROWSABLE_DIRS)
			ghost = 1;

		ret = master_add_autofs_point(entry, logopt, 0, ghost, 0);
		if (!ret) {
			error(m_logopt, "failed to add autofs_point");
			master_free_mapent(entry);
			goto next;
		}

		opts = conf_amd_get_map_options(path);
		if (opts) {
			/* autofs uses the equivalent of cache:=inc,sync
			 * (except for file maps which use cache:=all,sync)
			 * but if the map is large then it may be necessary
			 * to read the whole map at startup even if browsing
			 * is is not enabled, so look for cache:=all in the
			 * map_options configuration entry.
			 */
			if (strstr(opts, "cache:=all"))
				entry->ap->flags |= MOUNT_FLAG_AMD_CACHE_ALL;
			free(opts);
		}

		type = conf_amd_get_map_type(path);
		argv[0] = map;
		argv[1] = NULL;

		source = master_add_map_source(entry, type, "amd",
					       age, 1, (const char **) argv);
		if (!source) {
			error(m_logopt,
			      "failed to add source for amd section mount %s",
			      path);
			master_free_mapent(entry);
			goto next;
		}

		timeout = conf_amd_get_dismount_interval(path);
		set_exp_timeout(entry->ap, source, timeout);
		source->master_line = 0;

		entry->age = age;

		master_add_mapent(master, entry);
next:
		if (type)
			free(type);
		if (map)
			free(map);
		i++;
	}

	i = 0;
	while (paths[i])
		free(paths[i++]);
	free(paths);
}

static void wait_for_lookups_and_lock(struct master *master)
{
	struct list_head *p, *head;
	int status;

again:
	master_mutex_lock();

	head = &master->mounts;
	p = head->next;
	while (p != head) {
		struct master_mapent *this;

		this = list_entry(p, struct master_mapent, list);

		status = pthread_rwlock_trywrlock(&this->source_lock);
		if (status) {
			struct timespec t = { 0, 200000000 };
			struct timespec r;

			master_mutex_unlock();

			while (nanosleep(&t, &r) == -1 && errno == EINTR)
				memcpy(&t, &r, sizeof(struct timespec));

			goto again;
		}
		master_source_unlock(this);

		p = p->next;
	}
}

int master_read_master(struct master *master, time_t age)
{
	unsigned int logopt = master->logopt;
	struct mapent_cache *nc;
	int ret = 1;

	/*
	 * We need to clear and re-populate the null map entry cache
	 * before alowing anyone else to use it.
	 */
	wait_for_lookups_and_lock(master);
	pthread_cleanup_push(master_mutex_lock_cleanup, NULL);
	if (master->nc) {
		cache_writelock(master->nc);
		nc = master->nc;
		cache_clean_null_cache(nc);
	} else {
		nc = cache_init_null_cache(master);
		if (!nc) {
			error(logopt,
			      "failed to init null map cache for %s",
			      master->name);
			ret = 0;
			goto done;
		}
		cache_writelock(nc);
		master->nc = nc;
	}
	master_init_scan();
	lookup_nss_read_master(master, age);
	cache_unlock(nc);
	master_add_amd_mount_section_mounts(master, age);

	if (!master->read_fail)
		master_mount_mounts(master, age);
	else {
		master->read_fail = 0;
		/* HUP signal sets master->readall == 1 only */
		if (!master->readall) {
			ret = 0;
			goto done;
		} else
			master_mount_mounts(master, age);
	}

	if (__master_list_empty(master))
		warn(logopt, "no mounts in table");
done:
	pthread_cleanup_pop(1);

	return ret;
}

int master_notify_submount(struct autofs_point *ap, const char *path, enum states state)
{
	struct mnt_list *this, *sbmnt;
	int ret = 1;

	this = mnts_find_submount(path);
	if (this) {
		/* We have found a submount to expire */
		st_mutex_lock();

		if (this->ap->state == ST_SHUTDOWN) {
			this = NULL;
			st_mutex_unlock();
			goto done;
		}

		this->ap->shutdown = ap->shutdown;

		__st_add_task(this->ap, state);

		st_mutex_unlock();

		st_wait_task(this->ap, state, 0);

		/*
		 * If our submount gets to state ST_SHUTDOWN_PENDING or
		 * ST_SHUTDOWN_FORCE we need to wait until it goes away
		 * or changes to state ST_SHUTDOWN or ST_READY.
		 */
		st_mutex_lock();
		while ((sbmnt = mnts_find_submount(path))) {
			struct timespec t = { 0, 300000000 };
			struct timespec r;

			if (sbmnt->ap->state != ST_SHUTDOWN_PENDING &&
			    sbmnt->ap->state != ST_SHUTDOWN_FORCE) {
				ret = 0;
				mnts_put_mount(sbmnt);
				break;
			}
			mnts_put_mount(sbmnt);

			st_mutex_unlock();
			while (nanosleep(&t, &r) == -1 && errno == EINTR)
				memcpy(&t, &r, sizeof(struct timespec));
			st_mutex_lock();
		}
		st_mutex_unlock();
done:
		mnts_put_mount(this);
	}

	return ret;
}

void master_notify_state_change(struct master *master, int sig)
{
	struct master_mapent *entry;
	struct autofs_point *ap;
	struct list_head *p;
	int cur_state;
	unsigned int logopt;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	master_mutex_lock();

	list_for_each(p, &master->mounts) {
		enum states next = ST_INVAL;

		entry = list_entry(p, struct master_mapent, list);

		ap = entry->ap;
		logopt = ap->logopt;

		st_mutex_lock();

		if (ap->state == ST_SHUTDOWN)
			goto next;

		switch (sig) {
		case SIGTERM:
		case SIGINT:
			if (ap->state != ST_SHUTDOWN_PENDING &&
			    ap->state != ST_SHUTDOWN_FORCE) {
				next = ST_SHUTDOWN_PENDING;
				ap->shutdown = 1;
				__st_add_task(ap, next);
			}
			break;
#ifdef ENABLE_FORCED_SHUTDOWN
		case SIGUSR2:
			if (ap->state != ST_SHUTDOWN_FORCE &&
			    ap->state != ST_SHUTDOWN_PENDING) {
				next = ST_SHUTDOWN_FORCE;
				ap->shutdown = 1;
				__st_add_task(ap, next);
			}
			break;
#endif
		case SIGUSR1:
			assert(ap->state == ST_READY);
			next = ST_PRUNE;
			__st_add_task(ap, next);
			break;
		}
next:
		if (next != ST_INVAL)
			debug(logopt,
			      "sig %d switching %s from %d to %d",
			      sig, ap->path, ap->state, next);

		st_mutex_unlock();
	}

	master_mutex_unlock();
	pthread_setcancelstate(cur_state, NULL);

	return;
}

static int master_do_mount(struct master_mapent *entry)
{
	struct startup_cond suc;
	struct autofs_point *ap;
	pthread_t thid;
	int status;

	ap = entry->ap;

	if (handle_mounts_startup_cond_init(&suc)) {
		crit(ap->logopt,
		     "failed to init startup cond for mount %s", entry->path);
		return 0;
	}

	suc.ap = ap;
	suc.done = 0;
	suc.status = 0;

	if (!(do_force_unlink & UNLINK_AND_EXIT))
		debug(ap->logopt, "mounting %s", entry->path);

	status = pthread_create(&thid, &th_attr, handle_mounts, &suc);
	if (status) {
		crit(ap->logopt,
		     "failed to create mount handler thread for %s",
		     entry->path);
		handle_mounts_startup_cond_destroy(&suc);
		return 0;
	}

	while (!suc.done) {
		status = pthread_cond_wait(&suc.cond, &suc.mutex);
		if (status)
			fatal(status);
	}

	if (suc.status) {
		if (!(do_force_unlink & UNLINK_AND_EXIT))
			error(ap->logopt, "failed to startup mount");
		handle_mounts_startup_cond_destroy(&suc);
		return 0;
	}
	ap->thid = thid;

	handle_mounts_startup_cond_destroy(&suc);

	return 1;
}

static void check_update_map_sources(struct master_mapent *entry, int readall)
{
	struct map_source *source, *last;
	struct autofs_point *ap;
	int map_stale = 0;

	if (readall)
		map_stale = 1;

	ap = entry->ap;

	master_source_writelock(entry);

	last = NULL;
	source = entry->maps;
	while (source) {
		if (readall)
			source->stale = 1;

		/*
		 * If a map source is no longer valid and all it's
		 * entries have expired away we can get rid of it.
		 */
		if (entry->age > source->age) {
			struct mapent *me;
			cache_readlock(source->mc);
			me = cache_lookup_first(source->mc);
			if (!me) {
				struct map_source *next = source->next;

				cache_unlock(source->mc);

				if (!last)
					entry->maps = next;
				else
					last->next = next;

				if (entry->maps == source)
					entry->maps = next;

				master_free_map_source(source, 1);

				source = next;
				continue;
			} else {
				source->stale = 1;
				map_stale = 1;
			}
			cache_unlock(source->mc);
		}
		last = source;
		source = source->next;
	}

	master_source_unlock(entry);

	/* The map sources have changed */
	if (map_stale)
		st_add_task(ap, ST_READMAP);

	return;
}

int master_mount_mounts(struct master *master, time_t age)
{
	struct mapent_cache *nc = master->nc;
	struct list_head *p, *head;
	int cur_state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);

	head = &master->mounts;
	p = head->next;
	while (p != head) {
		struct master_mapent *this;
		struct autofs_point *ap;
		struct mapent *ne, *nested;

		this = list_entry(p, struct master_mapent, list);
		p = p->next;

		ap = this->ap;

		/* A master map entry has gone away */
		if (this->age < age) {
			st_add_task(ap, ST_SHUTDOWN_PENDING);
			continue;
		}

		cache_writelock(nc);
		ne = cache_lookup_distinct(nc, this->path);
		/*
		 * If this path matched a nulled entry the master map entry
		 * must be an indirect mount so the master map entry line
		 * number may be obtained from this->maps.
		 */
		if (ne) {
			int lineno = ne->age;

			cache_unlock(nc);
			/* null entry appears after map entry */
			if (this->maps->master_line < lineno) {
				warn(ap->logopt,
				     "ignoring null entry that appears after "
				     "existing entry for %s", this->path);
				goto cont;
			}
			if (ap->state != ST_INIT) {
				st_add_task(ap, ST_SHUTDOWN_PENDING);
				continue;
			}
			/*
			 * The map entry hasn't been started yet and we've
			 * seen a preceeding null map entry for it so just
			 * delete it from the master map entry list so it
			 * doesn't get in the road.
			 */
			list_del_init(&this->list);
			master_free_mapent_sources(ap->entry, 1);
			master_free_mapent(ap->entry);
			continue;
		}

		nested = cache_partial_match(nc, this->path);
		if (nested) {
			error(ap->logopt,
			     "removing invalid nested null entry %s",
			     nested->key);
			cache_delete(nc, nested->key);
		}
		cache_unlock(nc);
cont:
		if (ap->thid && ap->state != ST_INIT)
			check_update_map_sources(this, master->readall);
		else {
			if (!master_do_mount(this)) {
				list_del_init(&this->list);
				master_free_mapent_sources(ap->entry, 1);
				master_free_mapent(ap->entry);
			}
		}
	}

	pthread_setcancelstate(cur_state, NULL);

	return 1;
}

/* The nss source instances end up in reverse order. */
static void list_source_instances(struct map_source *source, struct map_source *instance)
{
	if (!source || !instance) {
		printf("none");
		return;
	}

	if (instance->next)
		list_source_instances(source, instance->next);

	/*
	 * For convienience we map nss instance type "files" to "file".
	 * Check for that and report corrected instance type.
	 */
	if (strcmp(instance->type, "file"))
		printf("%s ", instance->type);
	else {
		if (source->argv && *(source->argv[0]) != '/')
			printf("files ");
		else
			printf("%s ", instance->type);
	}

	return;
}

static void print_map_info(struct map_source *source)
{
	int argc = source->argc;
	int i, multi, map_num;

	multi = (source->type && !strcmp(source->type, "multi"));
	map_num = 1;
	for (i = 0; i < argc; i++) {
		if (source->argv[i] && *source->argv[i] != '-') {
			if (!multi)
				printf("  map: %s\n", source->argv[i]);
			else
				printf("  map[%i]: %s\n", map_num, source->argv[i]);
			i++;
		}

		if (i >= argc)
			return;

		if (!strcmp(source->argv[i], "--"))
			continue;

		if (source->argv[i]) {
			int need_newline = 0;
			int j;

			if (!multi)
				printf("  arguments:");
			else
				printf("  arguments[%i]:", map_num);

			for (j = i; j < source->argc; j++) {
				if (!strcmp(source->argv[j], "--"))
					break;
				printf(" %s", source->argv[j]);
				i++;
				need_newline = 1;
			}
			if (need_newline)
				printf("\n");
		}
		if (multi)
			map_num++;
	}

	return;
}

static int match_type(const char *source, const char *type)
{
	if (!strcmp(source, type))
		return 1;
	/* Sources file and files are synonymous */
	if (!strncmp(source, type, 4) && (strlen(source) <= 5))
		return 1;
	return 0;
}

static char *get_map_name(const char *string)
{
	char *name, *tmp;
	char *start, *end, *base;

	tmp = strdup(string);
	if (!tmp) {
		printf("error: allocation failure: %s\n", strerror(errno));
		return NULL;
	}

	base = basename(tmp);
	end = strchr(base, ',');
	if (end)
		*end = '\0';
	start = strchr(tmp, '=');
	if (start)
		start++;
	else {
		char *colon = strrchr(base, ':');
		if (colon)
			start = ++colon;
		else
			start = base;
	}

	name = strdup(start);
	if (!name)
		printf("error: allocation failure: %s\n", strerror(errno));
	free(tmp);

	return name;
}

static int match_name(struct map_source *source, const char *name)
{
	int argc = source->argc;
	int ret = 0;
	int i;

	/*
	 * This can't work for old style "multi" type sources since
	 * there's no way to know from which map the cache entry came
	 * from and duplicate entries are ignored at map read time.
	 * All we can really do is list all the entries for the given
	 * multi map if one of its map names matches.
	 */
	for (i = 0; i < argc; i++) {
		if (i == 0 || !strcmp(source->argv[i], "--")) {
			if (i != 0) {
				i++;
				if (i >= argc)
					break;
			}

			if (source->argv[i] && *source->argv[i] != '-') {
				char *map = get_map_name(source->argv[i]);
				if (!map)
					break;
				if (!strcmp(map, name)) {
					ret = 1;
					free(map);
					break;
				}
				free(map);
			}
		}
	}

	return ret;
}

int dump_map(struct master *master, const char *type, const char *name)
{
	struct list_head *p, *head;

	if (__master_list_empty(master)) {
		printf("no master map entries found\n");
		return 1;
	}

	head = &master->mounts;
	p = head->next;
	while (p != head) {
		struct map_source *source;
		struct master_mapent *this;
		struct autofs_point *ap;
		time_t now = monotonic_time(NULL);

		this = list_entry(p, struct master_mapent, list);
		p = p->next;

		ap = this->ap;

		/*
		 * Ensure we actually read indirect map entries so we can
		 * list them. The map reads won't read any indirect map
		 * entries (other than those in a file map) unless the
		 * browse option is set.
		 */
		if (ap->type == LKP_INDIRECT)
			ap->flags |= MOUNT_FLAG_GHOST;

		/* Read the map content into the cache */
		if (lookup_nss_read_map(ap, NULL, now))
			lookup_prune_cache(ap, now);
		else {
			printf("failed to read map\n");
			lookup_close_lookup(ap);
			continue;
		}

		if (!this->maps) {
			printf("no map sources found for %s\n", ap->path);
			lookup_close_lookup(ap);
			continue;
		}

		source = this->maps;
		while (source) {
			struct map_source *instance;
			struct mapent *me;

			instance = NULL;
			if (source->type) {
				if (!match_type(source->type, type)) {
					source = source->next;
					continue;
				}
				if (!match_name(source, name)) {
					source = source->next;
					continue;
				}
				instance = source;
			} else {
				struct map_source *map;

				map = source->instance;
				while (map) {
					if (!match_type(map->type, type)) {
						map = map->next;
						continue;
					}
					if (!match_name(map, name)) {
						map = map->next;
						continue;
					}
					instance = map;
					break;
				}
			}

			if (!instance) {
				source = source->next;
				lookup_close_lookup(ap);
				continue;
			}

			me = cache_lookup_first(source->mc);
			if (!me)
				printf("no keys found in map\n");
			else {
				do {
					if (me->source == instance)
						printf("%s\t%s\n", me->key, me->mapent);
				} while ((me = cache_lookup_next(source->mc, me)));
			}

			lookup_close_lookup(ap);
			return 1;
		}
		lookup_close_lookup(ap);
	}

	return 0;
}

int master_show_mounts(struct master *master)
{
	struct list_head *p, *head;

	printf("\nautofs dump map information\n"
		 "===========================\n\n");

	printf("global options: ");
	if (!global_options)
		printf("none configured\n");
	else {
		printf("%s\n", global_options);
		unsigned int append_options = defaults_get_append_options();
		const char *append = append_options ? "will" : "will not";
		printf("global options %s be appended to map entries\n", append);
	}

	if (__master_list_empty(master)) {
		printf("no master map entries found\n\n");
		return 1;
	}

	head = &master->mounts;
	p = head->next;
	while (p != head) {
		struct map_source *source;
		struct master_mapent *this;
		struct autofs_point *ap;
		time_t now = monotonic_time(NULL);
		unsigned int count = 0;

		this = list_entry(p, struct master_mapent, list);
		p = p->next;

		ap = this->ap;

		printf("\nMount point: %s\n", ap->path);

		printf("\nsource(s):\n");

		/*
		 * Ensure we actually read indirect map entries so we can
		 * list them. The map reads won't read any indirect map
		 * entries (other than those in a file map) unless the
		 * browse option is set.
		 */
		if (ap->type == LKP_INDIRECT)
			ap->flags |= MOUNT_FLAG_GHOST;

		/* Read the map content into the cache */
		if (lookup_nss_read_map(ap, NULL, now))
			lookup_prune_cache(ap, now);
		else {
			printf("  failed to read map\n\n");
			continue;
		}

		if (!this->maps) {
			printf("  no map sources found\n\n");
			continue;
		}

		source = this->maps;
		while (source) {
			struct mapent *me;

			if (source->type)
				printf("\n  type: %s\n", source->type);
			else {
				printf("\n  instance type(s): ");
				list_source_instances(source, source->instance);
				printf("\n");
			}

			if (source->argc >= 1) {
				print_map_info(source);
				if (count && ap->type == LKP_INDIRECT)
					printf("  duplicate indirect map entry"
					       " will be ignored at run time\n");
			}

			printf("\n");

			me = cache_lookup_first(source->mc);
			if (!me)
				printf("  no keys found in map\n");
			else {
				do {
					printf("  %s | %s\n", me->key, me->mapent);
				} while ((me = cache_lookup_next(source->mc, me)));
			}

			count++;

			source = source->next;
		}

		lookup_close_lookup(ap);

		printf("\n");
	}

	return 1;
}

int __master_list_empty(struct master *master)
{
	int res = 0;

	if (list_empty(&master->mounts))
		res = 1;

	return res;
}

int master_list_empty(struct master *master)
{
	int res;

	master_mutex_lock();
	res = __master_list_empty(master);
	master_mutex_unlock();

	return res;
}

int master_done(struct master *master)
{
	struct list_head *head, *p;
	struct master_mapent *entry;
	int res = 0;

	head = &master->completed;
	p = head->next;
	while (p != head) {
		entry = list_entry(p, struct master_mapent, join);
		p = p->next;
		list_del(&entry->join);
		pthread_join(entry->ap->thid, NULL);
		master_free_mapent_sources(entry, 1);
		master_free_mapent(entry);
	}

	if (__master_list_empty(master))
		res = 1;

	return res;
}

unsigned int master_get_logopt(void)
{
	return master_list ? master_list->logopt : LOGOPT_NONE;
}

int master_kill(struct master *master)
{
	if (!master)
		return 1;

	if (!master_list_empty(master))
		return 0;

	if (master->name)
		free(master->name);

	cache_release_null_cache(master);
	free(master);

	master_list = NULL;

	return 1;
}
