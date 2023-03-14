/* ----------------------------------------------------------------------- *
 *   
 *  cache.c - mount entry cache management routines
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


#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "automount.h"

void cache_readlock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_rdlock(&mc->rwlock);
	if (status) {
		logmsg("mapent cache rwlock lock failed");
		fatal(status);
	}
	return;
}

void cache_writelock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_wrlock(&mc->rwlock);
	if (status) {
		logmsg("mapent cache rwlock lock failed");
		fatal(status);
	}
	return;
}

int cache_try_writelock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_trywrlock(&mc->rwlock);
	if (status) {
		logmsg("mapent cache rwlock busy");
		return 0;
	}
	return 1;
}

void cache_unlock(struct mapent_cache *mc)
{
	int status;

	status = pthread_rwlock_unlock(&mc->rwlock);
	if (status) {
		logmsg("mapent cache rwlock unlock failed");
		fatal(status);
	}
	return;
}

void cache_lock_cleanup(void *arg)
{
	struct mapent_cache *mc = (struct mapent_cache *) arg;

	cache_unlock(mc);
	return;
}

static inline void ino_index_lock(struct mapent_cache *mc)
{
	int status = pthread_mutex_lock(&mc->ino_index_mutex);
	if (status)
		fatal(status);
	return;
}

static inline void ino_index_unlock(struct mapent_cache *mc)
{
	int status = pthread_mutex_unlock(&mc->ino_index_mutex);
	if (status)
		fatal(status);
	return;
}

/* Save the cache entry mapent field onto a stack and set a new mapent */
int cache_push_mapent(struct mapent *me, char *mapent)
{
	struct stack *s;
	char *new;

	if (!me->mapent)
		return CHE_FAIL;

	if (!mapent)
		new = NULL;
	else {
		new = strdup(mapent);
		if (!new)
			return CHE_FAIL;
	}

	s = malloc(sizeof(struct stack));
	if (!s) {
		if (new)
			free(new);
		return CHE_FAIL;
	}
	memset(s, 0, sizeof(*s));

	s->mapent = me->mapent;
	s->age = me->age;
	me->mapent = new;

	if (me->stack)
		s->next = me->stack;
	me->stack = s;

	return CHE_OK;
}

/* Restore cache entry mapent to a previously saved mapent, discard current */
int cache_pop_mapent(struct mapent *me)
{
	struct stack *s = me->stack;
	char *mapent;
	time_t age;

	if (!s || !s->mapent)
		return CHE_FAIL;

	mapent = s->mapent;
	age = s->age;
	me->stack = s->next;
	free(s);

	if (age < me->age) {
		free(mapent);
		return CHE_OK;
	}

	if (me->mapent)
		free(me->mapent);
	me->mapent = mapent;

	return CHE_OK;
}

struct mapent_cache *cache_init(struct autofs_point *ap, struct map_source *map)
{
	struct mapent_cache *mc;
	unsigned int i;
	int status;

	if (map->mc)
		cache_release(map);

	mc = malloc(sizeof(struct mapent_cache));
	if (!mc)
		return NULL;

	mc->size = defaults_get_map_hash_table_size();

	mc->hash = malloc(mc->size * sizeof(struct mapent *));
	if (!mc->hash) {
		free(mc);
		return NULL;
	}

	mc->ino_index = malloc(mc->size * sizeof(struct list_head));
	if (!mc->ino_index) {
		free(mc->hash);
		free(mc);
		return NULL;
	}

	status = pthread_mutex_init(&mc->ino_index_mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_rwlock_init(&mc->rwlock, NULL);
	if (status)
		fatal(status);

	cache_writelock(mc);

	for (i = 0; i < mc->size; i++) {
		mc->hash[i] = NULL;
		INIT_LIST_HEAD(&mc->ino_index[i]);
	}

	mc->ap = ap;
	mc->map = map;

	cache_unlock(mc);

	return mc;
}

void cache_clean_null_cache(struct mapent_cache *mc)
{
	struct mapent *me, *next;
	int i;

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (me == NULL)
			continue;
		next = me->next;
		free(me->key);
		if (me->mapent)
			free(me->mapent);
		free(me);

		while (next != NULL) {
			me = next;
			next = me->next;
			free(me->key);
			free(me);
		}
		mc->hash[i] = NULL;
	}

	return;
}

struct mapent_cache *cache_init_null_cache(struct master *master)
{
	struct mapent_cache *mc;
	unsigned int i;
	int status;

	mc = malloc(sizeof(struct mapent_cache));
	if (!mc)
		return NULL;

	mc->size = NULL_MAP_HASHSIZE;

	mc->hash = malloc(mc->size * sizeof(struct mapent *));
	if (!mc->hash) {
		free(mc);
		return NULL;
	}

	mc->ino_index = malloc(mc->size * sizeof(struct list_head));
	if (!mc->ino_index) {
		free(mc->hash);
		free(mc);
		return NULL;
	}

	status = pthread_mutex_init(&mc->ino_index_mutex, NULL);
	if (status)
		fatal(status);

	status = pthread_rwlock_init(&mc->rwlock, NULL);
	if (status)
		fatal(status);

	for (i = 0; i < mc->size; i++) {
		mc->hash[i] = NULL;
		INIT_LIST_HEAD(&mc->ino_index[i]);
	}

	mc->ap = NULL;
	mc->map = NULL;

	return mc;
}

static u_int32_t ino_hash(dev_t dev, ino_t ino, unsigned int size)
{
	u_int32_t hashval;

	hashval = dev + ino;

	return hashval % size;
}

int cache_set_ino_index(struct mapent_cache *mc, struct mapent *me)
{
	u_int32_t ino_index = ino_hash(me->dev, me->ino, mc->size);

	ino_index_lock(mc);
	list_del_init(&me->ino_index);
	list_add(&me->ino_index, &mc->ino_index[ino_index]);
	ino_index_unlock(mc);

	return 1;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_ino(struct mapent_cache *mc, dev_t dev, ino_t ino)
{
	struct mapent *me = NULL;
	struct list_head *head, *p;
	u_int32_t ino_index;

	ino_index_lock(mc);
	ino_index = ino_hash(dev, ino, mc->size);
	head = &mc->ino_index[ino_index];

	list_for_each(p, head) {
		me = list_entry(p, struct mapent, ino_index);

		if (me->dev != dev || me->ino != ino)
			continue;

		ino_index_unlock(mc);
		return me;
	}
	ino_index_unlock(mc);
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_first(struct mapent_cache *mc)
{
	struct mapent *me = NULL;
	unsigned int i;

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (!me)
			continue;

		while (me) {
			/* Multi mount entries are not primary */
			if (IS_MM(me) && !IS_MM_ROOT(me)) {
				me = me->next;
				continue;
			}
			return me;
		}
	}
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_next(struct mapent_cache *mc, struct mapent *me)
{
	struct mapent *this;
	u_int32_t hashval;
	unsigned int i;

	if (!me)
		return NULL;

	this = me->next;
	while (this) {
		/* Multi mount entries are not primary */
		if (IS_MM(this) && !IS_MM_ROOT(this)) {
			this = this->next;
			continue;
		}
		return this;
	}

	hashval = hash(me->key, mc->size) + 1;
	if (hashval < mc->size) {
		for (i = (unsigned int) hashval; i < mc->size; i++) {
			this = mc->hash[i];
			if (!this)
				continue;

			while (this) {
				/* Multi mount entries are not primary */
				if (IS_MM(this) && !IS_MM_ROOT(this)) {
					this = this->next;
					continue;
				}
				return this;
			}
		}
	}
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_key_next(struct mapent *me)
{
	struct mapent *next;

	if (!me)
		return NULL;

	next = me->next;
	while (next) {
		/* Multi mount entries are not primary */
		if (IS_MM(me) && !IS_MM_ROOT(me))
			continue;
		if (!strcmp(me->key, next->key))
			return next;
		next = next->next;
	}
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup(struct mapent_cache *mc, const char *key)
{
	struct mapent *me = NULL;

	if (!key)
		return NULL;

	for (me = mc->hash[hash(key, mc->size)]; me != NULL; me = me->next) {
		if (strcmp(key, me->key) == 0)
			goto done;
	}

	me = cache_lookup_first(mc);
	if (me != NULL) {
		/* Can't have wildcard in direct map */
		if (*me->key == '/') {
			me = NULL;
			goto done;
		}

		for (me = mc->hash[hash("*", mc->size)]; me != NULL; me = me->next)
			if (strcmp("*", me->key) == 0)
				goto done;
	}
done:
	return me;
}

/* cache must be read locked by caller */
struct mapent *cache_lookup_distinct(struct mapent_cache *mc, const char *key)
{
	struct mapent *me;

	if (!key)
		return NULL;

	for (me = mc->hash[hash(key, mc->size)]; me != NULL; me = me->next) {
		if (strcmp(key, me->key) == 0)
			return me;
	}

	return NULL;
}

/* cache must be read locked by caller */
static struct mapent *__cache_partial_match(struct mapent_cache *mc,
					    const char *prefix,
					    unsigned int type)
{
	struct mapent *me = NULL;
	size_t len = strlen(prefix);
	unsigned int i;

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (me == NULL)
			continue;

		if (len < strlen(me->key) &&
		    (strncmp(prefix, me->key, len) == 0) &&
		     me->key[len] == '/') {
			if (type == LKP_NORMAL)
				return me;
			if (type == LKP_WILD &&
			    me->key[len] != '\0' &&
			    me->key[len + 1] == '*')
				return me;
		}

		me = me->next;
		while (me != NULL) {
			if (len < strlen(me->key) &&
			    (strncmp(prefix, me->key, len) == 0 &&
			    me->key[len] == '/')) {
				if (type == LKP_NORMAL)
					return me;
				if (type == LKP_WILD &&
				    me->key[len] != '\0' &&
				    me->key[len + 1] == '*')
					return me;
			}
			me = me->next;
		}
	}
	return NULL;
}

/* cache must be read locked by caller */
struct mapent *cache_partial_match(struct mapent_cache *mc, const char *prefix)
{
	return __cache_partial_match(mc, prefix, LKP_NORMAL);
}

/* cache must be read locked by caller */
struct mapent *cache_partial_match_wild(struct mapent_cache *mc, const char *prefix)
{
	return __cache_partial_match(mc, prefix, LKP_WILD);
}

/* cache must be write locked by caller */
int cache_add(struct mapent_cache *mc, struct map_source *ms, const char *key, const char *mapent, time_t age)
{
	struct mapent *me, *existing = NULL;
	char *pkey, *pent;
	u_int32_t hashval = hash(key, mc->size);
	size_t len;

	me = (struct mapent *) malloc(sizeof(struct mapent));
	if (!me)
		return CHE_FAIL;

	len = strlen(key);

	pkey = malloc(len + 1);
	if (!pkey) {
		free(me);
		return CHE_FAIL;
	}
	me->key = strcpy(pkey, key);
	me->len = len;

	if (mapent) {
		pent = malloc(strlen(mapent) + 1);
		if (!pent) {
			free(me);
			free(pkey);
			return CHE_FAIL;
		}
		me->mapent = strcpy(pent, mapent);
	} else
		me->mapent = NULL;

	me->stack = NULL;

	me->age = age;
	me->status = 0;
	me->mc = mc;
	me->source = ms;
	me->mm_root = NULL;
	me->mm_parent = NULL;
	INIT_TREE_NODE(&me->node);
	INIT_LIST_HEAD(&me->ino_index);
	INIT_LIST_HEAD(&me->work);
	me->ioctlfd = -1;
	me->dev = (dev_t) -1;
	me->ino = (ino_t) -1;
	me->flags = 0;
	me->next = NULL;

	/* 
	 * We need to add to the end if values exist in order to
	 * preserve the order in which the map was read on lookup.
	 */
	existing = cache_lookup_distinct(mc, key);
	if (!existing) {
		me->next = mc->hash[hashval];
		mc->hash[hashval] = me;
	} else {
		while (1) {
			struct mapent *next;
		
			next = cache_lookup_key_next(existing);
			if (!next)
				break;

			existing = next;
		}
		existing->next = me;
	}
	return CHE_OK;
}

/* cache must be write locked by caller */
int cache_update_offset(struct mapent_cache *mc, const char *mkey, const char *key, const char *mapent, time_t age)
{
	unsigned logopt = mc->ap ? mc->ap->logopt : master_get_logopt();
	struct mapent *me, *owner;
	int ret = CHE_OK;

	owner = cache_lookup_distinct(mc, mkey);
	if (!owner)
		return CHE_FAIL;

	me = cache_lookup_distinct(mc, key);
	if (me && me->age == age) {
		if (me == owner || strcmp(me->key, key) == 0) {
			char *pent;

			warn(logopt,
			     "duplcate offset detected for key %s", me->key);

			pent = malloc(strlen(mapent) + 1);
			if (!pent)
				warn(logopt,
				     "map entry not updated: %s", me->mapent);
			else {
				if (me->mapent)
					free(me->mapent);
				me->mapent = strcpy(pent, mapent);
				warn(logopt,
				     "map entry updated with: %s", mapent);
			}
			return CHE_DUPLICATE;
		}
	}

	ret = cache_update(mc, owner->source, key, mapent, age);
	if (ret == CHE_FAIL) {
		warn(logopt, "failed to add key %s to cache", key);
		return CHE_FAIL;
	}

	return ret; 
}

/* Called with cache_lock held for map entry me and is released
 * on return.
 */
int cache_lookup_negative(struct mapent *me, const char *key)
{
	if (me->status >= monotonic_time(NULL)) {
		cache_unlock(me->mc);
		return CHE_UNAVAIL;
	} else {
		struct mapent_cache *smc = me->mc;
		struct mapent *sme;

		if (me->mapent)
			cache_unlock(smc);
		else {
			cache_unlock(smc);
			cache_writelock(smc);
			sme = cache_lookup_distinct(smc, key);
			/* Negative timeout expired for non-existent entry. */
			if (sme && !sme->mapent) {
				if (cache_pop_mapent(sme) == CHE_FAIL)
					cache_delete(smc, key);
			}
			cache_unlock(smc);
		}
	}

	return CHE_OK;
}

void cache_update_negative(struct mapent_cache *mc,
			   struct map_source *ms, const char *key,
			   time_t timeout)
{
	time_t now = monotonic_time(NULL);
	struct mapent *me;
	int rv = CHE_OK;

	/* Don't update the wildcard */
	if (strlen(key) == 1 && *key == '*')
		return;

	me = cache_lookup_distinct(mc, key);
	if (me)
		rv = cache_push_mapent(me, NULL);
	else
		rv = cache_update(mc, ms, key, NULL, now);
	if (rv != CHE_FAIL) {
		me = cache_lookup_distinct(mc, key);
		if (me)
			me->status = now + timeout;
	}
	return;
}


struct mapent *cache_get_offset_parent(struct mapent_cache *mc, const char *key)
{
	struct mapent *me;
	char *parent, *tail;
	int key_len;

	key_len = strlen(key);

	/* Check if this is the root offset */
	if (key[key_len - 1] == '/')
		return NULL;

	parent = strdup(key);
	tail = &parent[key_len - 1];

	while (*tail) {
		while (*tail != '/')
			tail--;

		*tail = 0;

		tail--;
		if (tail <= parent)
			break;

		me = cache_lookup_distinct(mc, parent);
		if (me) {
			free(parent);
			return me;
		}
	}
	free(parent);

	return NULL;
}

/* cache must be write locked by caller */
int cache_update(struct mapent_cache *mc, struct map_source *ms, const char *key, const char *mapent, time_t age)
{
	unsigned logopt = mc->ap ? mc->ap->logopt : master_get_logopt();
	struct mapent *me = NULL;
	char *pent;
	int ret = CHE_OK;

	me = cache_lookup(mc, key);
	while (me && me->source != ms)
		me = cache_lookup_key_next(me);
	if (!me || (!strcmp(me->key, "*") && strcmp(key, "*"))) {
		ret = cache_add(mc, ms, key, mapent, age);
		if (!ret) {
			debug(logopt, "failed for %s", key);
			return CHE_FAIL;
		}
		ret = CHE_UPDATED;
	} else {
		/* Already seen one of these */
		if (me->age == age)
			return CHE_OK;

		if (!mapent) {
			if (me->mapent)
				free(me->mapent);
			me->mapent = NULL;
		} else if (!me->mapent || strcmp(me->mapent, mapent) != 0) {
			pent = malloc(strlen(mapent) + 1);
			if (pent == NULL)
				return CHE_FAIL;
			if (me->mapent)
				free(me->mapent);
			me->mapent = strcpy(pent, mapent);
			ret = CHE_UPDATED;
		}
		me->age = age;
	}
	return ret;
}

/* cache must be write locked by caller */
int cache_delete(struct mapent_cache *mc, const char *key)
{
	struct mapent *me = NULL, *pred;
	u_int32_t hashval = hash(key, mc->size);
	int ret = CHE_OK;

	me = mc->hash[hashval];
	if (!me)
		goto done;

	while (me->next != NULL) {
		pred = me;
		me = me->next;
		if (strcmp(key, me->key) == 0) {
			struct stack *s = me->stack;
			if (IS_MM(me)) {
				ret = CHE_FAIL;
				goto done;
			}
			pred->next = me->next;
			ino_index_lock(mc);
			list_del(&me->ino_index);
			ino_index_unlock(mc);
			free(me->key);
			if (me->mapent)
				free(me->mapent);
			while (s) {
				struct stack *next = s->next;
				if (s->mapent)
					free(s->mapent);
				free(s);
				s = next;
			}
			free(me);
			me = pred;
		}
	}

	me = mc->hash[hashval];
	if (!me)
		goto done;

	if (strcmp(key, me->key) == 0) {
		struct stack *s = me->stack;
		if (IS_MM(me)) {
			ret = CHE_FAIL;
			goto done;
		}
		mc->hash[hashval] = me->next;
		ino_index_lock(mc);
		list_del(&me->ino_index);
		ino_index_unlock(mc);
		free(me->key);
		if (me->mapent)
			free(me->mapent);
		while (s) {
			struct stack *next = s->next;
			if (s->mapent)
				free(s->mapent);
			free(s);
			s = next;
		}
		free(me);
	}
done:
	return ret;
}

void cache_release(struct map_source *map)
{
	struct mapent_cache *mc;
	struct mapent *me, *next;
	int status;
	unsigned int i;

	mc = map->mc;

	cache_writelock(mc);

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (me == NULL)
			continue;
		next = me->next;
		free(me->key);
		if (me->mapent)
			free(me->mapent);
		free(me);

		while (next != NULL) {
			me = next;
			next = me->next;
			free(me->key);
			if (me->mapent)
				free(me->mapent);
			free(me);
		}
	}

	map->mc = NULL;

	cache_unlock(mc);

	status = pthread_mutex_destroy(&mc->ino_index_mutex);
	if (status)
		fatal(status);

	status = pthread_rwlock_destroy(&mc->rwlock);
	if (status)
		fatal(status);

	free(mc->hash);
	free(mc->ino_index);
	free(mc);
}

void cache_release_null_cache(struct master *master)
{
	struct mapent_cache *mc;
	struct mapent *me, *next;
	int status;
	unsigned int i;

	mc = master->nc;

	cache_writelock(mc);

	for (i = 0; i < mc->size; i++) {
		me = mc->hash[i];
		if (me == NULL)
			continue;
		next = me->next;
		free(me->key);
		if (me->mapent)
			free(me->mapent);
		free(me);

		while (next != NULL) {
			me = next;
			next = me->next;
			free(me->key);
			free(me);
		}
	}

	master->nc = NULL;

	cache_unlock(mc);

	status = pthread_mutex_destroy(&mc->ino_index_mutex);
	if (status)
		fatal(status);

	status = pthread_rwlock_destroy(&mc->rwlock);
	if (status)
		fatal(status);

	free(mc->hash);
	free(mc->ino_index);
	free(mc);
}



/* cache must be read locked by caller */
struct mapent *cache_enumerate(struct mapent_cache *mc, struct mapent *me)
{
	if (!me)
		return cache_lookup_first(mc);

	return cache_lookup_next(mc, me);
}
