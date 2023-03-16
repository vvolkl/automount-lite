/* ----------------------------------------------------------------------- *
 *   
 *  lookup_hosts.c - module for Linux automount to mount the exports
 *                      from a given host
 *
 *   Copyright 2005 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <malloc.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"
#define MODPREFIX "lookup(hosts): "

pthread_mutex_t hostent_mutex = PTHREAD_MUTEX_INITIALIZER;

struct lookup_context {
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt,
		int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];

	*context = NULL;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	mapfmt = MAPFMT_DEFAULT;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc, argv);
	if (!ctxt->parse) {
		logerr(MODPREFIX "failed to open parse context");
		free(ctxt);
		return 1;
	}

	*context = ctxt;

	return 0;
}

int lookup_reinit(const char *mapfmt,
		  int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt = (struct lookup_context *) *context;
	int ret;

	mapfmt = MAPFMT_DEFAULT;

	ret = reinit_parse(ctxt->parse, mapfmt, MODPREFIX, argc, argv);
	if (ret)
		return 1;

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	return NSS_STATUS_UNKNOWN;
}

struct work_info {
	char *mapent;
	const char *host;
	int pos;
};

static int tree_host_work(struct tree_node *n, void *ptr)
{
	struct exportinfo *exp = EXPORTINFO(n);
	struct work_info *wi = ptr;
	int len;

	if (!wi->pos)
		len = sprintf(wi->mapent, "\"%s\" \"%s:%s\"",
				exp->dir, wi->host, exp->dir);
	else
		len = sprintf(wi->mapent + wi->pos, " \"%s\" \"%s:%s\"",
				exp->dir, wi->host, exp->dir);
	wi->pos += len;

	return 1;
}

static char *get_exports(struct autofs_point *ap, const char *host)
{
	char buf[MAX_ERR_BUF];
	char *mapent;
	struct exportinfo *exp, *this;
	struct tree_node *tree = NULL;
	struct work_info wi;
	size_t hostlen = strlen(host);
	size_t mapent_len;

	debug(ap->logopt, MODPREFIX "fetchng export list for %s", host);

	exp = rpc_get_exports(host, 10, 0, RPC_CLOSE_NOLINGER);

	this = exp;
	mapent_len = 0;
	while (this) {
		struct tree_node *n;

		mapent_len += hostlen + 2*(strlen(this->dir) + 2) + 3;

		if (!tree) {
			tree = tree_host_root(this);
			if (!tree) {
				error(ap->logopt, "failed to create exports tree root");
				rpc_exports_free(exp);
				return NULL;
			}
			goto next;
		}

		n = tree_host_add_node(tree, this);
		if (!n) {
			error(ap->logopt, "failed to add exports tree node");
			tree_free(tree);
			rpc_exports_free(exp);
			return NULL;
		}
next:
		this = this->next;
	}

	mapent = malloc(mapent_len + 1);
	if (!mapent) {
		char *estr;
		estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, MODPREFIX "malloc: %s", estr);
		error(ap->logopt, MODPREFIX "exports lookup failed for %s", host);
		rpc_exports_free(exp);
		return NULL;
	}
	*mapent = 0;

	wi.mapent = mapent;
	wi.host = host;
	wi.pos = 0;

	if (!tree) {
		free(mapent);
		mapent = NULL;
	} else {
		tree_traverse_inorder(tree, tree_host_work, &wi);
		tree_free(tree);
	}
	rpc_exports_free(exp);

	return mapent;
}

static int do_parse_mount(struct autofs_point *ap, struct map_source *source,
			  const char *name, int name_len, char *mapent,
			  struct lookup_context *ctxt)
{
	int ret;

	ret = ctxt->parse->parse_mount(ap, source, name, name_len,
				 mapent, ctxt->parse->context);
	if (ret) {
		struct mapent_cache *mc = source->mc;

		/* Don't update negative cache when re-connecting */
		if (ap->flags & MOUNT_FLAG_REMOUNT)
			return NSS_STATUS_TRYAGAIN;
		cache_writelock(mc);
		cache_update_negative(mc, source, name, ap->negative_timeout);
		cache_unlock(mc);
		return NSS_STATUS_TRYAGAIN;
	}
	return NSS_STATUS_SUCCESS;
}

struct update_context {
	char *key;
	int key_len;
	char *entry;
	struct update_context *next;
};

static int add_update_entry(struct update_context **entries, struct mapent *me)
{
	struct update_context *upd;
	char *key, *ent;

	key = strdup(me->key);
	if (!key)
		return 0;

	ent = strdup(me->mapent);
	if (!ent) {
		free(key);
		return 0;
	}

	upd = malloc(sizeof(struct update_context));
	if (!upd) {
		free(ent);
		free(key);
		return 0;
	}

	upd->key = key;
	upd->key_len = me->len;
	upd->entry = ent;
	upd->next = NULL;
	if (*entries)
		(*entries)->next = upd;
	*entries = upd;

	return 1;
}

static void free_update_entries(struct update_context *entries)
{
	struct update_context *this = entries;

	while (this) {
		struct update_context *next = this->next;
		free(this->key);
		free(this->entry);
		free(this);
		this = next;
	}
}

void entries_cleanup(void *arg)
{
	struct update_context *entries = arg;

	free_update_entries(entries);
}

static void update_hosts_mounts(struct autofs_point *ap,
				struct map_source *source, time_t age,
				struct lookup_context *ctxt)
{
	struct update_context *head = NULL;
	struct update_context *entries = NULL;
	struct mapent_cache *mc;
	struct mapent *me;
	char *mapent;
	int ret;

	mc = source->mc;

	pthread_cleanup_push(entries_cleanup, head);

	pthread_cleanup_push(cache_lock_cleanup, mc);
	cache_writelock(mc);
	me = cache_lookup_first(mc);
	while (me) {
		/* Hosts map entry not yet expanded or already expired */
		if (!IS_MM(me))
			goto next;

		debug(ap->logopt, MODPREFIX "get list of exports for %s", me->key);

		mapent = get_exports(ap, me->key);
		if (mapent) {
			int ret;

			ret = cache_update(mc, source, me->key, mapent, age);
			free(mapent);
			if (!IS_MM_ROOT(me))
				goto next;
			if (ret != CHE_FAIL) {
				if (!add_update_entry(&entries, me))
					warn(ap->logopt, MODPREFIX
					     "failed to add update entry for %s", me->key);
				else if (!head)
					head = entries;
			}
		}
next:
		me = cache_lookup_next(mc, me);
	}
	pthread_cleanup_pop(1);

	entries = head;
	while (entries) {
		debug(ap->logopt, MODPREFIX
		      "attempt to update exports for %s", entries->key);

		ap->flags |= MOUNT_FLAG_REMOUNT;
		ret = ctxt->parse->parse_mount(ap, source, entries->key,
					       strlen(entries->key), entries->entry,
					       ctxt->parse->context);
		if (ret)
			warn(ap->logopt, MODPREFIX
			     "failed to parse mount %s", entries->entry);
		ap->flags &= ~MOUNT_FLAG_REMOUNT;
		entries = entries->next;
	}
	pthread_cleanup_pop(1);
}

int lookup_read_map(struct autofs_point *ap, struct map_source *map, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source = map;
	struct mapent_cache *mc = source->mc;
	struct hostent *host;
	int status;

	debug(ap->logopt, MODPREFIX "read hosts map");

	/*
	 * If we don't need to create directories then there's no use
	 * reading the map. We always need to read the whole map for
	 * direct mounts in order to mount the triggers.
	 */
	if (!(ap->flags & MOUNT_FLAG_GHOST) && ap->type != LKP_DIRECT) {
		debug(ap->logopt, MODPREFIX
		      "map not browsable, update existing host entries only");
		update_hosts_mounts(ap, source, age, ctxt);
		source->age = age;
		return NSS_STATUS_SUCCESS;
	}

	status = pthread_mutex_lock(&hostent_mutex);
	if (status) {
		error(ap->logopt, MODPREFIX "failed to lock hostent mutex");
		return NSS_STATUS_UNAVAIL;
	}

	sethostent(0);
	while ((host = gethostent()) != NULL) {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		cache_writelock(mc);
		cache_update(mc, source, host->h_name, NULL, age);
		cache_unlock(mc);
		pthread_cleanup_pop(0);
	}
	endhostent();

	status = pthread_mutex_unlock(&hostent_mutex);
	if (status)
		error(ap->logopt, MODPREFIX "failed to unlock hostent mutex");

	update_hosts_mounts(ap, source, age, ctxt);
	source->age = age;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, struct map_source *map, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source = map;
	struct mapent_cache *mc = source->mc;
	struct mapent *me;
	char *mapent = NULL;
	int mapent_len;
	time_t now = monotonic_time(NULL);
	int ret;

	/* Check if we recorded a mount fail for this key anywhere */
	me = lookup_source_mapent(ap, name, LKP_DISTINCT);
	if (me) {
		/* negative timeout has not passed, return fail */
		if (cache_lookup_negative(me, name) == CHE_UNAVAIL)
			return NSS_STATUS_NOTFOUND;
	}

	cache_readlock(mc);
	me = cache_lookup_distinct(mc, name);
	if (!me) {
		cache_unlock(mc);
		/*
		 * We haven't read the list of hosts into the
		 * cache so go straight to the lookup.
		 */
		if (!(ap->flags & MOUNT_FLAG_GHOST)) {
			/*
			 * If name contains a '/' we're searching for an
			 * offset that doesn't exist in the export list
			 * so it's NOTFOUND otherwise this could be a
			 * lookup for a new host.
			 */
			if (*name != '/' && strchr(name, '/'))
				return NSS_STATUS_NOTFOUND;
			goto done;
		}

		if (*name == '/')
			info(ap->logopt, MODPREFIX
			      "can't find path in hosts map %s", name);
		else
			info(ap->logopt, MODPREFIX
			      "can't find path in hosts map %s/%s",
			      ap->path, name);

		debug(ap->logopt,
		      MODPREFIX "lookup failed - update exports list");
		goto done;
	}
	/*
	 * Host map export entries are added to the cache as
	 * direct mounts. If the name we seek starts with a slash
	 * it must be a mount request for one of the exports.
	 */
	if (*name == '/') {
		pthread_cleanup_push(cache_lock_cleanup, mc);
		mapent_len = strlen(me->mapent);
		mapent = malloc(mapent_len + 1);
		if (mapent)
			strcpy(mapent, me->mapent);
		pthread_cleanup_pop(0);
	}
	cache_unlock(mc);

done:
	debug(ap->logopt, MODPREFIX "%s -> %s", name, mapent);

	if (!mapent) {
		/* We need to get the exports list and update the cache. */
		mapent = get_exports(ap, name);

		/* Exports lookup failed so we're outa here */
		if (!mapent)
			return NSS_STATUS_UNAVAIL;

		cache_writelock(mc);
		cache_update(mc, source, name, mapent, now);
		cache_unlock(mc);
	}

	ret = do_parse_mount(ap, source, name, name_len, mapent, ctxt);

	free(mapent);

	return ret;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	return rv;
}
