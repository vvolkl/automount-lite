/* ----------------------------------------------------------------------- *
 *   
 *  lookup.c - API layer to implement nsswitch semantics for map reading
 *		and mount lookups.
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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "automount.h"
#include "nsswitch.h"

extern long global_positive_timeout;

static void nsslist_cleanup(void *arg)
{
	struct list_head *nsslist = (struct list_head *) arg;
	if (!list_empty(nsslist))
		free_sources(nsslist);
	return;
}

static int do_read_master(struct master *master, char *type, time_t age)
{
	struct lookup_mod *lookup;
	const char *argv[2];
	int argc;
	int status;

	argc = 1;
	argv[0] = master->name;
	argv[1] = NULL;

	status = open_lookup(type, "", NULL, argc, argv, &lookup);
	if (status != NSS_STATUS_SUCCESS)
		return status;

	status = lookup->lookup_read_master(master, age, lookup->context);

	close_lookup(lookup);

	return status;
}

static char *find_map_path(struct autofs_point *ap, struct map_source *map)
{
	const char *mname = map->argv[0];
	unsigned int mlen = strlen(mname);
	char *tok, *ptr = NULL;
	char *path = NULL;
	char *search_path;
	struct stat st;

	/* Absolute path, just return a copy */
	if (mname[0] == '/')
		return strdup(mname);

	/*
	 * This is different to the way it is in amd.
	 * autofs will always try to locate maps in AUTOFS_MAP_DIR
	 * but amd has no default and will not find a file map that
	 * isn't a full path when no search_path is configured, either
	 * in the mount point or global configuration.
	 */
	search_path = strdup(AUTOFS_MAP_DIR);
	if (map->flags & MAP_FLAG_FORMAT_AMD) {
		struct autofs_point *pap = ap;
		char *tmp;
		/*
		 * Make sure we get search_path from the root of the
		 * mount tree, if one is present in the configuration.
		 * Again different from amd, which ignores the submount
		 * case.
		 */
		while (pap->parent)
			pap = pap->parent;
		tmp = conf_amd_get_search_path(pap->path);
		if (tmp) {
			if (search_path)
				free(search_path);
			search_path = tmp;
		}
	}
	if (!search_path)
		return NULL;

	tok = strtok_r(search_path, ":", &ptr);
	while (tok) {
		char *this = malloc(strlen(tok) + mlen + 2);
		if (!this) {
			free(search_path);
			return NULL;
		}
		strcpy(this, tok);
		strcat(this, "/");
		strcat(this, mname);
		if (!stat(this, &st)) {
			path = this;
			break;
		}
		free(this);
		tok = strtok_r(NULL, ":", &ptr);
	}

	free(search_path);
	return path;
}

static int read_master_map(struct master *master, char *type, time_t age)
{
	unsigned int logopt = master->logopt;
	char *path, *save_name;
	int result;

	if (strcasecmp(type, "files")) {
		return do_read_master(master, type, age);
	}

	/* 
	 * This is a special case as we need to append the
	 * normal location to the map name.
	 * note: It's invalid to specify a relative path.
	 */

	if (strchr(master->name, '/')) {
		error(logopt, "relative path invalid in files map name");
		return NSS_STATUS_NOTFOUND;
	}

	path = malloc(strlen(AUTOFS_MAP_DIR) + strlen(master->name) + 2);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	strcpy(path, AUTOFS_MAP_DIR);
	strcat(path, "/");
	strcat(path, master->name);

	save_name = master->name;
	master->name = path;

	result = do_read_master(master, type, age);

	master->name = save_name;
	free(path);

	return result;
}

int lookup_nss_read_master(struct master *master, time_t age)
{
	unsigned int logopt = master->logopt;
	struct list_head nsslist;
	struct list_head *head, *p;
	int result = NSS_STATUS_UNKNOWN;

	/* If it starts with a '/' it has to be a file or LDAP map */
	if (*master->name == '/') {
		if (*(master->name + 1) == '/') {
			info(logopt, "reading ldap master %s", master->name);
			result = do_read_master(master, "ldap", age);
		} else {
			debug(logopt, "reading master file %s", master->name);
			result = do_read_master(master, "file", age);
		}

		if (result == NSS_STATUS_UNAVAIL)
			master->read_fail = 1;

		return result;
	} else {
		char *name = master->name;
		char *tmp;

		/* Old style name specification will remain I think. */
		tmp = strchr(name, ':');
		if (tmp) {
			char source[10];

			memset(source, 0, 10);
			if ((!strncmp(name, "file", 4) &&
				 (name[4] == ',' || name[4] == ':')) ||
			    (!strncmp(name, "yp", 2) &&
				 (name[2] == ',' || name[2] == ':')) ||
			    (!strncmp(name, "nis", 3) &&
				 (name[3] == ',' || name[3] == ':')) ||
			    (!strncmp(name, "nisplus", 7) &&
				 (name[7] == ',' || name[7] == ':')) ||
			    (!strncmp(name, "ldap", 4) &&
				 (name[4] == ',' || name[4] == ':')) ||
			    (!strncmp(name, "ldaps", 5) &&
				 (name[5] == ',' || name[5] == ':')) ||
			    (!strncmp(name, "sss", 3) ||
				 (name[3] == ',' || name[3] == ':')) ||
			    (!strncmp(name, "dir", 3) &&
				 (name[3] == ',' || name[3] == ':'))) {
				strncpy(source, name, tmp - name);

				/*
				 * If it's an ldap map leave the source in the
				 * name so the lookup module can work out if
				 * ldaps has been requested.
				 */
				if (strncmp(name, "ldap", 4)) {
					master->name = tmp + 1;
					info(logopt, "reading %s master %s",
					      source, master->name);
				} else {
					master->name = name;
					debug(logopt, "reading master %s %s",
					      source, tmp + 1);
				}

				result = do_read_master(master, source, age);
				master->name = name;

				if (result == NSS_STATUS_UNAVAIL)
					master->read_fail = 1;

				return result;
			}
		}
	}

	INIT_LIST_HEAD(&nsslist);

	result = nsswitch_parse(&nsslist);
	if (result) {
		if (!list_empty(&nsslist))
			free_sources(&nsslist);
		error(logopt, "can't to read name service switch config.");
		return NSS_STATUS_UNAVAIL;
	}

	/* First one gets it */
	result = NSS_STATUS_SUCCESS;
	head = &nsslist;
	list_for_each(p, head) {
		struct nss_source *this;
		int status;

		this = list_entry(p, struct nss_source, list);

		if (strncmp(this->source, "files", 5) &&
		    strncmp(this->source, "nis", 3) &&
		    strncmp(this->source, "nisplus", 7) &&
		    strncmp(this->source, "ldap", 4) &&
		    strncmp(this->source, "sss", 3))
			continue;

		info(logopt,
		      "reading %s master %s", this->source, master->name);

		result = read_master_map(master, this->source, age);

		/*
		 * If the name of the master map hasn't been explicitly
		 * configured and we're not reading an included master map
		 * then we're using auto.master as the default. Many setups
		 * also use auto_master as the default master map so we
		 * check for this map when auto.master isn't found.
		 */
		if (result != NSS_STATUS_SUCCESS &&
		    !master->depth && !defaults_master_set()) {
			char *tmp = strchr(master->name, '.');
			if (tmp) {
				debug(logopt,
				      "%s not found, replacing '.' with '_'",
				       master->name);
				*tmp = '_';
				result = read_master_map(master, this->source, age);
				if (result != NSS_STATUS_SUCCESS)
					*tmp = '.';
			}
		}

		/* We've been instructed to move onto the next source */
		if (result == NSS_STATUS_TRYAGAIN) {
			result = NSS_STATUS_SUCCESS;
			continue;
		}

		if (result == NSS_STATUS_UNKNOWN ||
		    result == NSS_STATUS_NOTFOUND) {
			debug(logopt, "no map - continuing to next source");
			result = NSS_STATUS_SUCCESS;
			continue;
		}

		if (result == NSS_STATUS_UNAVAIL)
			master->read_fail = 1;

		status = check_nss_result(this, result);
		if (status >= 0)
			break;
	}

	if (!list_empty(&nsslist))
		free_sources(&nsslist);

	return result;
}

static int do_read_map(struct autofs_point *ap, struct map_source *map, time_t age)
{
	struct lookup_mod *lookup;
	int status;

	if (!map->stale)
		return NSS_STATUS_SUCCESS;

	/* If this readmap is the result of trying to mount a submount
	 * the readlock may already be held if the map is the same as
	 * that of the caller. In that case the map has already been
	 * read so just skip the map open/reinit.
	 */
	status = map_module_try_writelock(map);
	if (status) {
		if (!map->lookup) {
			error(ap->logopt, "map module lock not held as expected");
			return NSS_STATUS_UNAVAIL;
		}
	} else {
		if (!map->lookup) {
			pthread_cleanup_push(map_module_lock_cleanup, map);
			status = open_lookup(map->type, "", map->format,
					     map->argc, map->argv, &lookup);
			pthread_cleanup_pop(0);
			if (status != NSS_STATUS_SUCCESS) {
				map_module_unlock(map);
				debug(ap->logopt,
				      "lookup module %s open failed", map->type);
				return status;
			}
			map->lookup = lookup;
		} else {
			pthread_cleanup_push(map_module_lock_cleanup, map);
			status = map->lookup->lookup_reinit(map->format,
							    map->argc, map->argv,
							    &map->lookup->context);
			pthread_cleanup_pop(0);
			if (status) {
				map_module_unlock(map);
				warn(ap->logopt,
				     "lookup module %s reinit failed", map->type);
				return status;
			}
		}
		map_module_unlock(map);
	}

	pthread_cleanup_push(map_module_lock_cleanup, map);
	map_module_readlock(map);
	lookup = map->lookup;
	status = lookup->lookup_read_map(ap, map, age, lookup->context);
	pthread_cleanup_pop(1);

	if (status != NSS_STATUS_SUCCESS)
		map->stale = 0;

	/*
	 * For maps that don't support enumeration return success
	 * and do whatever we must to have autofs function with an
	 * empty map entry cache.
	 *
	 * For indirect maps that use the browse option, when the
	 * server is unavailable continue as best we can with
	 * whatever we have in the cache, if anything.
	 */
	if (status == NSS_STATUS_UNKNOWN ||
	   (ap->type == LKP_INDIRECT && status == NSS_STATUS_UNAVAIL))
		return NSS_STATUS_SUCCESS;

	return status;
}

static int read_file_source_instance(struct autofs_point *ap, struct map_source *map, time_t age)
{
	struct map_source *instance;
	char src_file[] = "file";
	char src_prog[] = "program";
	struct stat st;
	char *type, *format;
	char *path;

	if (map->argc < 1) {
		error(ap->logopt, "invalid arguments for autofs_point");
		return NSS_STATUS_UNKNOWN;
	}

	path = find_map_path(ap, map);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	if (stat(path, &st) == -1) {
		warn(ap->logopt, "file map %s not found", path);
		free(path);
		return NSS_STATUS_NOTFOUND;
	}

	if (!S_ISREG(st.st_mode)) {
		free(path);
		return NSS_STATUS_NOTFOUND;
	}

	if (st.st_mode & S_IEXEC)
		type = src_prog;
	else
		type = src_file;

	format = map->format;

	instance = master_find_source_instance(map, type, format, 0, NULL);
	if (!instance) {
		const char **argv;
		int argc;

		argc = map->argc;
		argv = copy_argv(map->argc, map->argv);
		if (!argv) {
			error(ap->logopt, "failed to copy args");
			free(path);
			return NSS_STATUS_UNKNOWN;
		}
		if (argv[0])
			free((char *) argv[0]);
		argv[0] = path;
		path = NULL;

		instance = master_add_source_instance(map, type, format, age, argc, argv);
		free_argv(argc, argv);
		if (!instance)
			return NSS_STATUS_UNAVAIL;
		instance->recurse = map->recurse;
		instance->depth = map->depth;
	}
	instance->stale = map->stale;

	if (path)
		free(path);

	return do_read_map(ap, instance, age);
}

static int read_source_instance(struct autofs_point *ap, struct map_source *map, const char *type, time_t age)
{
	struct map_source *instance;
	const char *format;

	format = map->format;

	instance = master_find_source_instance(map, type, format, 0, NULL);
	if (!instance) {
		int argc = map->argc;
		const char **argv = map->argv;
		instance = master_add_source_instance(map, type, format, age, argc, argv);
		if (!instance)
			return NSS_STATUS_UNAVAIL;
		instance->recurse = map->recurse;
		instance->depth = map->depth;
	}
	instance->stale = map->stale;

	return do_read_map(ap, instance, age);
}

static int lookup_map_read_map(struct autofs_point *ap,
			       struct map_source *map, time_t age)
{
	char *path;

	if (!map->argv[0]) {
		if (!strcmp(map->type, "hosts"))
			return do_read_map(ap, map, age);
		return NSS_STATUS_UNKNOWN;
	}

	/*
	 * This is only called when map->type != NULL.
	 * We only need to look for a map if source type is
	 * file and the map name doesn't begin with a "/".
	 */
	if (strncmp(map->type, "file", 4))
		return do_read_map(ap, map, age);

	if (map->argv[0][0] == '/')
		return do_read_map(ap, map, age);

	path = find_map_path(ap, map);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	if (map->argc >= 1) {
		if (map->argv[0])
			free((char *) map->argv[0]);
		map->argv[0] = path;
	} else {
		error(ap->logopt, "invalid arguments for autofs_point");
		free(path);
		return NSS_STATUS_UNKNOWN;
	}

	return do_read_map(ap, map, age);
}

static enum nsswitch_status read_map_source(struct nss_source *this,
		struct autofs_point *ap, struct map_source *map, time_t age)
{
	if (strcasecmp(this->source, "files")) {
		return read_source_instance(ap, map, this->source, age);
	}

	/* 
	 * This is a special case as we need to append the
	 * normal location to the map name.
	 * note: It's invalid to specify a relative path.
	 */

	if (strchr(map->argv[0], '/')) {
		error(ap->logopt, "relative path invalid in files map name");
		return NSS_STATUS_NOTFOUND;
	}

	return read_file_source_instance(ap, map, age);
}

int lookup_nss_read_map(struct autofs_point *ap, struct map_source *source, time_t age)
{
	struct master_mapent *entry = ap->entry;
	struct list_head nsslist;
	struct list_head *head, *p;
	struct nss_source *this;
	struct map_source *map;
	enum nsswitch_status status;
	unsigned int at_least_one = 0;
	int result = 0;

	/*
	 * For each map source (ie. each entry for the mount
	 * point in the master map) do the nss lookup to
	 * locate the map and read it.
	 */
	if (source)
		map = source;
	else
		map = entry->maps;
	while (map) {
		/* Is map source up to date or no longer valid */
		if (!map->stale || entry->age > map->age) {
			map = map->next;
			continue;
		}

		if (map->type) {
			if (!strncmp(map->type, "multi", 5))
				debug(ap->logopt, "reading multi map");
			else
				info(ap->logopt,
				      "reading %s map %s",
				       map->type, map->argv[0]);
			result = lookup_map_read_map(ap, map, age);
			map = map->next;
			continue;
		}

		/* If it starts with a '/' it has to be a file or LDAP map */
		if (map->argv && *map->argv[0] == '/') {
			if (*(map->argv[0] + 1) == '/') {
				char *tmp = strdup("ldap");
				if (!tmp) {
					map = map->next;
					continue;
				}
				map->type = tmp;
				info(ap->logopt,
				      "reading %s map %s", tmp, map->argv[0]);
				result = do_read_map(ap, map, age);
			} else {
				debug(ap->logopt,
				      "reading map file %s", map->argv[0]);
				result = read_file_source_instance(ap, map, age);
			}
			map = map->next;
			continue;
		}

		INIT_LIST_HEAD(&nsslist);

		pthread_cleanup_push(nsslist_cleanup, &nsslist);
		status = nsswitch_parse(&nsslist);
		pthread_cleanup_pop(0);
		if (status) {
			error(ap->logopt,
			      "can't to read name service switch config.");
			result = 1;
			break;
		}

		pthread_cleanup_push(nsslist_cleanup, &nsslist);
		head = &nsslist;
		list_for_each(p, head) {
			this = list_entry(p, struct nss_source, list);

			if (map->flags & MAP_FLAG_FORMAT_AMD &&
			    !strcmp(this->source, "sss")) {
				warn(ap->logopt,
				     "source sss is not available for amd maps.");
				continue;
			}

			info(ap->logopt,
			      "reading %s map %s", this->source, map->argv[0]);

			result = read_map_source(this, ap, map, age);
			if (result == NSS_STATUS_UNKNOWN)
				continue;

			/* Try to avoid updating the map cache if an instance
			 * is unavailable */
			if (result == NSS_STATUS_UNAVAIL)
				map->stale = 0;

			if (result == NSS_STATUS_SUCCESS) {
				at_least_one = 1;
				result = NSS_STATUS_TRYAGAIN;
			}

			status = check_nss_result(this, result);
			if (status >= 0) {
				map = NULL;
				break;
			}

			result = NSS_STATUS_SUCCESS;
		}
		pthread_cleanup_pop(1);

		if (!map)
			break;

		map = map->next;
	}

	if (!result || at_least_one)
		return 1;

	return 0;
}

static char *make_browse_path(unsigned int logopt,
			      const char *root, const char *key,
			      const char *prefix)
{
	unsigned int l_prefix;
	unsigned int k_len, r_len;
	char *k_start;
	char *path;

	k_start = (char *) key;
	k_len = strlen(key);
	l_prefix = 0;

	if (prefix) {
		l_prefix = strlen(prefix);

		if (l_prefix > k_len)
			return NULL;

		/* If the prefix doesn't match the beginning
		 * of the key this entry isn't a sub directory
		 * at this level.
		 */
		if (strncmp(key, prefix, l_prefix))
			return NULL;

		/* Directory entry starts following the prefix */
		k_start += l_prefix;
	}

	/* No remaining "/" allowed here */
	if (strchr(k_start, '/'))
		return NULL;

	r_len = strlen(root);

	if ((r_len + strlen(k_start)) > KEY_MAX_LEN)
		return NULL;

	path = malloc(r_len + k_len + 2);
	if (!path) {
		warn(logopt, "failed to allocate full path");
		return NULL;
	}

	sprintf(path, "%s/%s", root, k_start);

	return path;
}

int lookup_ghost(struct autofs_point *ap)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me;
	char buf[MAX_ERR_BUF];
	struct stat st;
	char *fullpath;
	int ret;

	if (!strcmp(ap->path, "/-"))
		return LKP_FAIL | LKP_DIRECT;

	if (!(ap->flags & MOUNT_FLAG_GHOST))
		return LKP_INDIRECT;

	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	map = entry->maps;
	while (map) {
		/*
		 * Only consider map sources that have been read since 
		 * the map entry was last updated.
		 */
		if (entry->age > map->age) {
			map = map->next;
			continue;
		}

		mc = map->mc;
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_readlock(mc);
		me = cache_enumerate(mc, NULL);
		while (me) {
			/*
			 * Map entries that have been created in the cache
			 * due to a negative lookup shouldn't have directories
			 * created if they haven't already been created.
			 */
			if (!me->mapent)
				goto next;

			/* Wildcard cannot be a browse directory and amd map
			 * keys may end with the wildcard.
			 */
			if (strchr(me->key, '*'))
				goto next;

			/* This will also take care of amd "/defaults" entry as
			 * amd map keys are not allowd to start with "/"
			 */
			if (*me->key == '/') {
				if (map->flags & MAP_FLAG_FORMAT_AMD)
					goto next;

				/* It's a busy multi-mount - leave till next time */
				if (IS_MM(me))
					error(ap->logopt,
					      "invalid key %s", me->key);
				goto next;
			}

			/* Ignore nulled indirect map entries */
			if (starts_with_null_opt(me->mapent))
				goto next;

			fullpath = make_browse_path(ap->logopt,
						    ap->path, me->key, ap->pref);
			if (!fullpath)
				goto next;

			ret = mkdir_path(fullpath, mp_mode);
			if (ret < 0) {
				if (errno != EEXIST) {
					char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
					warn(ap->logopt,
					     "mkdir_path %s failed: %s", fullpath, estr);
				}
				free(fullpath);
				goto next;
			}

			if (stat(fullpath, &st) != -1) {
				me->dev = st.st_dev;
				me->ino = st.st_ino;
			}

			free(fullpath);
next:
			me = cache_enumerate(mc, me);
		}
		pthread_cleanup_pop(1);
		map = map->next;
	}
	pthread_cleanup_pop(1);

	return LKP_INDIRECT;
}

int do_lookup_mount(struct autofs_point *ap, struct map_source *map, const char *name, int name_len)
{
	struct lookup_mod *lookup;
	int status;

	if (!map->lookup) {
		map_module_writelock(map);
		if (!map->lookup) {
			status = open_lookup(map->type, "",
					     map->format, map->argc, map->argv, &lookup);
			if (status != NSS_STATUS_SUCCESS) {
				map_module_unlock(map);
				debug(ap->logopt,
				      "lookup module %s open failed", map->type);
				return status;
			}
			map->lookup = lookup;
		}
		map_module_unlock(map);
	}

	map_module_readlock(map);
	lookup = map->lookup;
	status = lookup->lookup_mount(ap, map, name, name_len, lookup->context);
	map_module_unlock(map);

	return status;
}

static int lookup_amd_instance(struct autofs_point *ap,
			       struct map_source *map,
			       const char *name, int name_len)
{
	struct map_source *instance;
	struct mnt_list *mnt;
	const char *argv[2];
	const char **pargv = NULL;
	int argc = 0;
	struct mapent *me;
	char *m_key;

	me = cache_lookup_distinct(map->mc, name);
	if (!me || !IS_MM(me)) {
		error(ap->logopt, "expected multi mount entry not found");
		return NSS_STATUS_UNKNOWN;
	}

	m_key = malloc(ap->len + MM_ROOT(me)->len + 2);
	if (!m_key) {
		error(ap->logopt,
		     "failed to allocate storage for search key");
		return NSS_STATUS_UNKNOWN;
	}

	strcpy(m_key, ap->path);
	strcat(m_key, "/");
	strcat(m_key, MM_ROOT(me)->key);

	mnt = mnts_find_amdmount(m_key);
	free(m_key);

	if (!mnt) {
		error(ap->logopt, "expected amd mount entry not found");
		return NSS_STATUS_UNKNOWN;
	}

	if (strcmp(mnt->amd_type, "host")) {
		error(ap->logopt, "unexpected map type %s", mnt->amd_type);
		mnts_put_mount(mnt);
		return NSS_STATUS_UNKNOWN;
	}

	if (mnt->amd_opts && *mnt->amd_opts) {
		argv[0] = mnt->amd_opts;
		argv[1] = NULL;
		pargv = argv;
		argc = 1;
	}

	instance = master_find_source_instance(map, "hosts", "sun", argc, pargv);
	/* If this is an nss map instance it may have an amd host map sub instance */
	if (!instance && map->instance) {
		struct map_source *next = map->instance;
		while (next) {
			instance = master_find_source_instance(next,
						"hosts", "sun", argc, pargv);
			if (instance)
				break;
			next = next->next;
		}
	}
	if (!instance) {
		mnts_put_mount(mnt);
		error(ap->logopt, "expected hosts map instance not found");
		return NSS_STATUS_UNKNOWN;
	}
	mnts_put_mount(mnt);

	return do_lookup_mount(ap, instance, name, name_len);
}

static int lookup_name_file_source_instance(struct autofs_point *ap, struct map_source *map, const char *name, int name_len)
{
	struct map_source *instance;
	char src_file[] = "file";
	char src_prog[] = "program";
	time_t age = monotonic_time(NULL);
	struct stat st;
	char *type, *format;
	char *path;

	if (*name == '/' && map->flags & MAP_FLAG_FORMAT_AMD)
		return lookup_amd_instance(ap, map, name, name_len);

	if (map->argc < 1) {
		error(ap->logopt, "invalid arguments for autofs_point");
		return NSS_STATUS_UNKNOWN;
	}

	path = find_map_path(ap, map);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	if (stat(path, &st) == -1) {
		debug(ap->logopt, "file map not found");
		free(path);
		return NSS_STATUS_NOTFOUND;
	}

	if (!S_ISREG(st.st_mode)) {
		free(path);
		return NSS_STATUS_NOTFOUND;
	}

	if (st.st_mode & S_IEXEC)
		type = src_prog;
	else
		type = src_file;

	format = map->format;

	instance = master_find_source_instance(map, type, format, 0, NULL);
	if (!instance) {
		const char **argv;
		int argc;

		argc = map->argc;
		argv = copy_argv(map->argc, map->argv);
		if (!argv) {
			error(ap->logopt, "failed to copy args");
			free(path);
			return NSS_STATUS_UNKNOWN;
		}
		if (argv[0])
			free((char *) argv[0]);
		argv[0] = path;
		path = NULL;

		instance = master_add_source_instance(map, type, format, age, argc, argv);
		free_argv(argc, argv);
		if (!instance)
			return NSS_STATUS_NOTFOUND;
		instance->recurse = map->recurse;
		instance->depth = map->depth;
	}

	if (path)
		free(path);

	return do_lookup_mount(ap, instance, name, name_len);
}

static int lookup_name_source_instance(struct autofs_point *ap, struct map_source *map, const char *type, const char *name, int name_len)
{
	struct map_source *instance;
	const char *format;
	time_t age = monotonic_time(NULL);

	if (*name == '/' && map->flags & MAP_FLAG_FORMAT_AMD)
		return lookup_amd_instance(ap, map, name, name_len);

	format = map->format;

	instance = master_find_source_instance(map, type, format, 0, NULL);
	if (!instance) {
		int argc = map->argc;
		const char **argv = map->argv;
		instance = master_add_source_instance(map, type, format, age, argc, argv);
		if (!instance)
			return NSS_STATUS_NOTFOUND;
		instance->recurse = map->recurse;
		instance->depth = map->depth;
	}

	return do_lookup_mount(ap, instance, name, name_len);
}

static int do_name_lookup_mount(struct autofs_point *ap,
				struct map_source *map,
				const char *name, int name_len)
{
	char *path;

	if (!map->argv[0]) {
		if (!strcmp(map->type, "hosts"))
			return do_lookup_mount(ap, map, name, name_len);
		return NSS_STATUS_UNKNOWN;
	}

	if (*name == '/' && map->flags & MAP_FLAG_FORMAT_AMD)
		return lookup_amd_instance(ap, map, name, name_len);

	/*
	 * This is only called when map->type != NULL.
	 * We only need to look for a map if source type is
	 * file and the map name doesn't begin with a "/".
	 */
	if (strncmp(map->type, "file", 4))
		return do_lookup_mount(ap, map, name, name_len);

	if (map->argv[0][0] == '/')
		return do_lookup_mount(ap, map, name, name_len);

	path = find_map_path(ap, map);
	if (!path)
		return NSS_STATUS_UNKNOWN;

	if (map->argc >= 1) {
		if (map->argv[0])
			free((char *) map->argv[0]);
		map->argv[0] = path;
	} else {
		error(ap->logopt, "invalid arguments for autofs_point");
		free(path);
		return NSS_STATUS_UNKNOWN;
	}

	return do_lookup_mount(ap, map, name, name_len);
}

static enum nsswitch_status lookup_map_name(struct nss_source *this,
			struct autofs_point *ap, struct map_source *map,
			const char *name, int name_len)
{
	if (strcasecmp(this->source, "files"))
		return lookup_name_source_instance(ap, map,
					this->source, name, name_len);

	/* 
	 * autofs build-in map for nsswitch "files" is "file".
	 * This is a special case as we need to append the
	 * normal location to the map name.
	 * note: we consider it invalid to specify a relative
	 *       path.
	 */
	if (strchr(map->argv[0], '/')) {
		error(ap->logopt, "relative path invalid in files map name");
		return NSS_STATUS_NOTFOUND;
	}

	return lookup_name_file_source_instance(ap, map, name, name_len);
}

static struct map_source *lookup_get_map_source(struct master_mapent *entry)
{
	struct map_source *map = entry->maps;
	struct stat st;
	char *type;

	if (map->type || *map->argv[0] != '/')
		return map;

	if (*(map->argv[0] + 1) == '/')
		return map;

	if (stat(map->argv[0], &st) == -1)
		return NULL;

	if (!S_ISREG(st.st_mode))
		return NULL;

	if (st.st_mode & S_IEXEC)
		type = "program";
	else
		type = "file";

	/* This is a file source with a path starting with "/".
	 * But file maps can be either plain text or executable
	 * so they use a map instance and the actual map source
	 * remains untouched.
	 */
	return master_find_source_instance(map, type, map->format, 0, NULL);
}

static void update_negative_cache(struct autofs_point *ap, struct map_source *source, const char *name)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent *me;

	/* Don't update negative cache for included maps */ 
	if (source && source->depth)
		return;

	/* Don't update the wildcard */
	if (strlen(name) == 1 && *name == '*')
		return;

	/* Have we recorded the lookup fail for negative caching? */
	me = lookup_source_mapent(ap, name, LKP_DISTINCT);
	if (me)
		/*
		 *  Already exists in the cache, the mount fail updates
		 *  will update negative timeout status.
		 */
		cache_unlock(me->mc);
	else {
		if (!defaults_disable_not_found_message()) {
			/* This really should be a warning but the original
			 * request for this needed it to be unconditional.
			 * That produces, IMHO, unnecessary noise in the log
			 * so a configuration option has been added to provide
			 * the ability to turn it off.
			 */
			logmsg("key \"%s\" not found in map source(s).", name);
		}

		/* Doesn't exist in any source, just add it somewhere.
		 * Also take care to use the same map source used by
		 * map reads and key lookups for the update.
		 */
		if (source)
			map = source;
		else
			map = lookup_get_map_source(entry);
		if (map) {
			time_t now = monotonic_time(NULL);
			int rv = CHE_FAIL;

			cache_writelock(map->mc);
			me = cache_lookup_distinct(map->mc, name);
			if (me)
				rv = cache_push_mapent(me, NULL);
			else
				rv = cache_update(map->mc, map, name, NULL, now);
			if (rv != CHE_FAIL) {
				me = cache_lookup_distinct(map->mc, name);
				if (me)
					me->status = now + ap->negative_timeout;
			}
			cache_unlock(map->mc);
		}
	}
	return;
}

int lookup_nss_mount(struct autofs_point *ap, struct map_source *source, const char *name, int name_len)
{
	struct master_mapent *entry = ap->entry;
	struct list_head nsslist;
	struct list_head *head, *p;
	struct nss_source *this;
	struct map_source *map;
	enum nsswitch_status status;
	int result = NSS_STATUS_UNKNOWN;

	/*
	 * For each map source (ie. each entry for the mount
	 * point in the master map) do the nss lookup to
	 * locate the map and lookup the name.
	 */
	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);
	if (source)
		map = source;
	else
		map = entry->maps;
	while (map) {
		/*
		 * Only consider map sources that have been read since 
		 * the map entry was last updated.
		 */
		if (entry->age > map->age) {
			status = NSS_STATUS_UNAVAIL;
			map = map->next;
			continue;
		}

		sched_yield();

		if (map->type) {
			result = do_name_lookup_mount(ap, map, name, name_len);
			if (result == NSS_STATUS_SUCCESS)
				break;

			map = map->next;
			continue;
		}

		/* If it starts with a '/' it has to be a file or LDAP map */
		if (*map->argv[0] == '/') {
			if (*(map->argv[0] + 1) == '/') {
				char *tmp = strdup("ldap");
				if (!tmp) {
					map = map->next;
					status = NSS_STATUS_TRYAGAIN;
					continue;
				}
				map->type = tmp;
				result = do_lookup_mount(ap, map, name, name_len);
			} else
				result = lookup_name_file_source_instance(ap, map, name, name_len);

			if (result == NSS_STATUS_SUCCESS)
				break;

			map = map->next;
			continue;
		}

		INIT_LIST_HEAD(&nsslist);

		status = nsswitch_parse(&nsslist);
		if (status) {
			error(ap->logopt,
			      "can't to read name service switch config.");
			result = 1;
			break;
		}

		head = &nsslist;
		list_for_each(p, head) {
			this = list_entry(p, struct nss_source, list);

			if (map->flags & MAP_FLAG_FORMAT_AMD &&
			    !strcmp(this->source, "sss")) {
				warn(ap->logopt,
				     "source sss is not available for amd maps.");
				result = NSS_STATUS_UNAVAIL;
				continue;
			}

			result = lookup_map_name(this, ap, map, name, name_len);

			if (result == NSS_STATUS_UNKNOWN)
				continue;

			status = check_nss_result(this, result);
			if (status >= 0) {
				map = NULL;
				break;
			}
		}

		if (!list_empty(&nsslist))
			free_sources(&nsslist);

		if (!map)
			break;

		map = map->next;
	}
	if (ap->state != ST_INIT)
		send_map_update_request(ap);

	/*
	 * The last source lookup will return NSS_STATUS_NOTFOUND if the
	 * map exits and the key has not been found but the map may also
	 * not exist in which case the key is also not found.
	 */
	if (result == NSS_STATUS_NOTFOUND || result == NSS_STATUS_UNAVAIL)
		update_negative_cache(ap, source, name);
	pthread_cleanup_pop(1);

	return !result;
}

static void lookup_close_lookup_instances(struct map_source *map)
{
	struct map_source *instance;

	instance = map->instance;
	while (instance) {
		lookup_close_lookup_instances(instance);
		instance = instance->next;
	}

	if (map->lookup) {
		close_lookup(map->lookup);
		map->lookup = NULL;
	}
}

void lookup_close_lookup(struct autofs_point *ap)
{
	struct map_source *map;

	map = ap->entry->maps;
	if (!map)
		return;

	while (map) {
		lookup_close_lookup_instances(map);
		map = map->next;
	}

	return;
}

static char *make_fullpath(struct autofs_point *ap, const char *key)
{
	char *path = NULL;
	int l;

	if (*key != '/')
		path = make_browse_path(ap->logopt, ap->path, key, ap->pref);
	else {
		l = strlen(key) + 1;
		if (l > KEY_MAX_LEN)
			goto out;
		path = malloc(l);
		if (!path)
			goto out;
		strcpy(path, key);
	}
out:
	return path;
}

void lookup_prune_one_cache(struct autofs_point *ap, struct mapent_cache *mc, time_t age)
{
	struct mapent *me, *this;
	char *path;
	int status = CHE_FAIL;

	me = cache_enumerate(mc, NULL);
	while (me) {
		struct mapent *valid;
		char *key = NULL, *next_key = NULL;

		if (me->age >= age) {
			/*
			 * Reset time of last fail for valid map entries to
			 * force entry update and subsequent mount retry.
			 * A map entry that's still invalid after a read
			 * may have been created by a failed wildcard lookup
			 * so reset the status on those too.
			 */
			if (me->mapent || cache_lookup(mc, "*"))
				me->status = 0;
			me = cache_enumerate(mc, me);
			continue;
		}

		if (ap->type == LKP_INDIRECT) {
			/* Don't prune offset map entries since they are
			 * created on demand and managed by expire and don't
			 * prune the multi-map owner map entry.
			 */
			if (*me->key == '/' || IS_MM_ROOT(me)) {
				me = cache_enumerate(mc, me);
				continue;
			}

			/* If the map hasn't been read (nobrowse
			 * indirect mounts) then keep cached entries
			 * for ap->positive_timeout.
			 */
			if (!(ap->flags & (MOUNT_FLAG_GHOST |
					   MOUNT_FLAG_AMD_CACHE_ALL))) {
				time_t until = me->age + ap->positive_timeout;
				if ((long) age - (long) until < 0) {
					me = cache_enumerate(mc, me);
					continue;
				}
			}
		}

		key = strdup(me->key);
		/* Don't consider any entries with a wildcard */
		if (!key || strchr(key, '*')) {
			if (key)
				free(key);
			me = cache_enumerate(mc, me);
			continue;
		}

		path = make_fullpath(ap, key);
		if (!path) {
			warn(ap->logopt, "can't malloc storage for path");
			free(key);
			me = cache_enumerate(mc, me);
			continue;
		}

		/*
		 * If this key has another valid entry we want to prune it,
		 * even if it's a mount, as the valid entry will take the
		 * mount if it is a direct mount or it's just a stale indirect
		 * cache entry.
		 */
		valid = lookup_source_valid_mapent(ap, key, LKP_DISTINCT);
		if (valid && valid->mc == mc) {
			 /*
			  * We've found a map entry that has been removed from
			  * the current cache so it isn't really valid. Set the
			  * mapent negative to prevent further mount requests
			  * using the cache entry.
			  */
			debug(ap->logopt, "removed map entry detected, mark negative");
			if (valid->mapent) {
				free(valid->mapent);
				valid->mapent = NULL;
			}
			cache_unlock(valid->mc);
			valid = NULL;
		}
		if (!valid &&
		    is_mounted(path, MNTS_REAL)) {
			debug(ap->logopt, "prune postponed, %s mounted", path);
			free(key);
			free(path);
			me = cache_enumerate(mc, me);
			continue;
		}
		if (valid)
			cache_unlock(valid->mc);

		me = cache_enumerate(mc, me);
		if (me)
			next_key = strdup(me->key);

		cache_unlock(mc);

		cache_writelock(mc);
		this = cache_lookup_distinct(mc, key);
		if (!this) {
			cache_unlock(mc);
			goto next;
		}

		if (valid)
			cache_delete(mc, key);
		else if (!is_mounted(path, MNTS_AUTOFS)) {
			dev_t devid = ap->dev;
			status = CHE_FAIL;
			if (ap->type == LKP_DIRECT)
				devid = this->dev;
			if (this->ioctlfd == -1)
				status = cache_delete(mc, key);
			if (status != CHE_FAIL) {
				if (ap->type == LKP_INDIRECT) {
					if (ap->flags & MOUNT_FLAG_GHOST)
						rmdir_path(ap, path, devid);
				} else
					rmdir_path(ap, path, devid);
			}
		}
		cache_unlock(mc);

next:
		cache_readlock(mc);
		if (next_key) {
			/* The lock release and reaquire above can mean
			 * a number of things could happen.
			 *
			 * First, mapents could be added between the
			 * current mapent and the mapent of next_key.
			 * Don't care about that because there's no
			 * need to prune newly added entries.
			 *
			 * Second, the next mapent data could have
			 * changed. Don't care about that either since
			 * we are looking to prune stale map entries
			 * and don't care when they become stale.
			 *
			 * Finally, the mapent of next_key could have
			 * gone away. Again don't care about this either,
			 * the loop will exit prematurely so just wait
			 * until the next prune and try again.
			 */
			me = cache_lookup_distinct(mc, next_key);
			free(next_key);
		}
		free(key);
		free(path);
	}

	return;
}

int lookup_prune_cache(struct autofs_point *ap, time_t age)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;

	pthread_cleanup_push(master_source_lock_cleanup, entry);
	master_source_readlock(entry);

	map = entry->maps;
	while (map) {
		/* Is the map stale */
		if (!map->stale && !check_stale_instances(map)) {
			map = map->next;
			continue;
		}
		pthread_cleanup_push(cache_lock_cleanup, map->mc);
		cache_readlock(map->mc);
		lookup_prune_one_cache(ap, map->mc, age);
		pthread_cleanup_pop(1);
		clear_stale_instances(map);
		map->stale = 0;
		map = map->next;
	}

	pthread_cleanup_pop(1);

	return 1;
}

/* Return with cache readlock held */
struct mapent *lookup_source_valid_mapent(struct autofs_point *ap, const char *key, unsigned int type)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me = NULL;

	map = entry->maps;
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
		if (type == LKP_DISTINCT)
			me = cache_lookup_distinct(mc, key);
		else
			me = cache_lookup(mc, key);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}

	return me;
}

/* Return with cache readlock held */
struct mapent *lookup_source_mapent(struct autofs_point *ap, const char *key, unsigned int type)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me = NULL;

	map = entry->maps;
	while (map) {
		mc = map->mc;
		cache_readlock(mc);
		if (type == LKP_DISTINCT)
			me = cache_lookup_distinct(mc, key);
		else
			me = cache_lookup(mc, key);
		if (me)
			break;
		cache_unlock(mc);
		map = map->next;
	}

	if (me && me->mc != mc)
		error(LOGOPT_ANY, "mismatching mc in cache", me->key);

	return me;
}

int lookup_source_close_ioctlfd(struct autofs_point *ap, const char *key)
{
	struct master_mapent *entry = ap->entry;
	struct map_source *map;
	struct mapent_cache *mc;
	struct mapent *me;
	int ret = 0;

	map = entry->maps;
	while (map) {
		mc = map->mc;
		cache_readlock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me) {
			if (me->ioctlfd != -1) {
				struct ioctl_ops *ops = get_ioctl_ops();
				ops->close(ap->logopt, me->ioctlfd);
				me->ioctlfd = -1;
			}
			cache_unlock(mc);
			ret = 1;
			break;
		}
		cache_unlock(mc);
		map = map->next;
	}

	return ret;
}

