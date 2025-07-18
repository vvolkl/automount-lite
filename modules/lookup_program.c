/* ----------------------------------------------------------------------- *
 *   
 *  lookup_program.c - module for Linux automount to access an
 *                     automount map via a query program 
 *
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <ctype.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(program): "

#ifdef ENABLE_STATIC_BUILD
/* Forward declarations for static parse modules */
extern int parse_sun_init(int argc, const char *const *argv, void **context);
extern int parse_sun_reinit(int argc, const char *const *argv, void **context);
extern int parse_sun_mount(struct autofs_point *ap, struct map_source *source, const char *name, int name_len, const char *mapent, void *context);
extern int parse_sun_done(void *context);
#endif

struct lookup_context {
	const char *mapname;
	char *mapfmt;
	struct parse_mod *parse;
};

struct parse_context {
	char *optstr;		/* Mount options */
	char *macros;		/* Map wide macro defines */
	struct substvar *subst;	/* $-substitutions */
	int slashify_colons;	/* Change colons to slashes? */
};

#ifndef ENABLE_STATIC_BUILD
int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */
#endif

static int do_init(const char *mapfmt,
		   int argc, const char *const *argv,
		   struct lookup_context *ctxt, unsigned int reinit)
{
	int ret = 0;

	if (argc < 1) {
		logmsg(MODPREFIX "No map name");
		ret = 1;
		goto out;
	}
	ctxt->mapname = argv[0];

	if (ctxt->mapname[0] != '/') {
		logmsg(MODPREFIX "program map %s is not an absolute pathname",
		     ctxt->mapname);
		ret = 1;
		goto out;
	}

	if (access(ctxt->mapname, X_OK)) {
		logmsg(MODPREFIX "program map %s missing or not executable",
		     ctxt->mapname);
		ret = 1;
		goto out;
	}

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	ctxt->mapfmt = strdup(mapfmt);
	if (!ctxt->mapfmt) {
		logmsg(MODPREFIX "failed to allocate storage for map format");
		ret = 1;
		goto out;
	}

	if (reinit) {
#ifdef ENABLE_STATIC_BUILD
		/* For static builds, we only support sun parser */
		if (strcmp(mapfmt, "sun") == 0) {
			ret = parse_sun_reinit(argc - 1, argv + 1, &ctxt->parse->context);
			if (ret)
				logmsg(MODPREFIX "failed to reinit parse context");
		} else {
			logmsg(MODPREFIX "parse format %s not supported in static build", mapfmt);
			ret = 1;
		}
#else
		ret = reinit_parse(ctxt->parse, mapfmt, MODPREFIX, argc - 1, argv + 1);
		if (ret)
			logmsg(MODPREFIX "failed to reinit parse context");
#endif
	} else {
#ifdef ENABLE_STATIC_BUILD
		/* For static builds, create a static parse module */
		if (strcmp(mapfmt, "sun") == 0) {
			ctxt->parse = malloc(sizeof(struct parse_mod));
			if (ctxt->parse) {
				ctxt->parse->parse_init = parse_sun_init;
				ctxt->parse->parse_reinit = parse_sun_reinit;
				ctxt->parse->parse_mount = parse_sun_mount;
				ctxt->parse->parse_done = parse_sun_done;
				ctxt->parse->dlhandle = NULL;

				if (parse_sun_init(argc - 1, argv + 1, &ctxt->parse->context)) {
					free(ctxt->parse);
					ctxt->parse = NULL;
					logmsg(MODPREFIX "failed to init parse context");
					ret = 1;
				}
			} else {
				logmsg(MODPREFIX "failed to allocate parse context");
				ret = 1;
			}
		} else {
			logmsg(MODPREFIX "parse format %s not supported in static build", mapfmt);
			ret = 1;
		}
#else
		ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
		if (!ctxt->parse) {
			logmsg(MODPREFIX "failed to open parse context");
			ret = 1;
		}
#endif
	}
out:
	if (ret && ctxt->mapfmt)
		free(ctxt->mapfmt);

	return ret;
}

int lookup_program_init(const char *mapfmt,
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
	memset(ctxt, 0, sizeof(struct lookup_context));

	if (do_init(mapfmt, argc, argv, ctxt, 0)) {
		free(ctxt);
		return 1;
	}

	*context = ctxt;

	return 0;
}

int lookup_program_reinit(const char *mapfmt,
		  int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt = (struct lookup_context *) *context;
	struct lookup_context *new;
	char buf[MAX_ERR_BUF];
	int ret;

	new = malloc(sizeof(struct lookup_context));
	if (!new) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}
	memset(new, 0, sizeof(struct lookup_context));

	new->parse = ctxt->parse;
	ret = do_init(mapfmt, argc, argv, new, 1);
	if (ret) {
		free(new);
		return 1;
	}

	*context = new;

	free(ctxt->mapfmt);
	free(ctxt);

	return 0;
}

int lookup_program_read_master(struct master *master, time_t age, void *context)
{
        return NSS_STATUS_UNKNOWN;
}

int lookup_program_read_map(struct autofs_point *ap, struct map_source *map, time_t age, void *context)
{
	return NSS_STATUS_UNKNOWN;
}

static char *lookup_one(struct autofs_point *ap,
			const char *name, int name_len,
			struct lookup_context *ctxt)
{
	char *mapent = NULL, *mapp, *tmp;
	char buf[MAX_ERR_BUF];
	char errbuf[1024], *errp;
	char ch;
	int pipefd[2], epipefd[2];
	struct pollfd pfd[2];
	pid_t f;
	enum state { st_space, st_map, st_done } state;
	int quoted = 0;
	int distance;
	int alloci = 1;
	int status;
	char *prefix;

	mapent = (char *) malloc(MAPENT_MAX_LEN + 1);
	if (!mapent) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return NULL;
	}

	/*
	 * By default use a prefix with standard environment
	 * variables to prevent system subversion by interpreted
	 * languages.
	 */
	if (defaults_force_std_prog_map_env())
		prefix = NULL;
	else
		prefix = "AUTOFS_";

	/*
	 * We don't use popen because we don't want to run /bin/sh plus we
	 * want to send stderr to the syslog, and we don't use spawnl()
	 * because we need the pipe hooks
	 */
	if (open_pipe(pipefd))
		goto out_error;
	if (open_pipe(epipefd)) {
		close(pipefd[0]);
		close(pipefd[1]);
		goto out_error;
	}

	open_mutex_lock();
	f = fork();
	if (f < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "fork: %s", estr);
		close(pipefd[0]);
		close(pipefd[1]);
		close(epipefd[0]);
		close(epipefd[1]);
		open_mutex_unlock();
		goto out_error;
	} else if (f == 0) {
		reset_signals();
		close(pipefd[0]);
		close(epipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(epipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		close(epipefd[1]);
		if (chdir(ap->path))
			warn(ap->logopt,
			     MODPREFIX "failed to set PWD to %s for map %s",
			     ap->path, ctxt->mapname);

		/*
		 * MAPFMT_DEFAULT must be "sun" for ->parse_init() to have setup
		 * the macro table.
		 */
		if (ctxt->mapfmt && !strcmp(ctxt->mapfmt, MAPFMT_DEFAULT)) {
			struct parse_context *pctxt = (struct parse_context *) ctxt->parse->context;
			/* Add standard environment as seen by sun map parser */
			pctxt->subst = addstdenv(pctxt->subst, prefix);
			macro_setenv(pctxt->subst);
		}
		execl(ctxt->mapname, ctxt->mapname, name, NULL);
		_exit(255);	/* execl() failed */
	}
	close(pipefd[1]);
	close(epipefd[1]);
	open_mutex_unlock();

	mapp = mapent;
	errp = errbuf;
	state = st_space;

	pfd[0].fd = pipefd[0];
	pfd[0].events = POLLIN;
	pfd[1].fd = epipefd[0];
	pfd[1].events = POLLIN;

	while (1) {
		int bytes;

		if (poll(pfd, 2, -1) < 0 && errno != EINTR)
			break;

		if (pfd[0].fd == -1 && pfd[1].fd == -1)
			break;

		if ((pfd[0].revents & (POLLIN|POLLHUP)) == POLLHUP &&
		    (pfd[1].revents & (POLLIN|POLLHUP)) == POLLHUP)
			break;

		/* Parse maps from stdout */
		if (pfd[0].revents) {
cont:
			bytes = read(pipefd[0], &ch, 1);
			if (bytes == 0)
				goto next;
			else if (bytes < 0) {
				pfd[0].fd = -1;
				state = st_done;
				goto next;
			}

			if (!quoted && ch == '\\') {
				quoted = 1;
				goto cont;
			}

			switch (state) {
			case st_space:
				if (quoted || !isspace(ch)) {
					*mapp++ = ch;
					state = st_map;
				}
				break;
			case st_map:
				if (!quoted && ch == '\n') {
					*mapp = '\0';
					state = st_done;
					break;
				}

				/* We overwrite up to 3 characters, so we
				 * need to make sure we have enough room
				 * in the buffer for this. */
				/* else */
				if (mapp - mapent > 
				    ((MAPENT_MAX_LEN+1) * alloci) - 3) {
					/*
					 * Alloc another page for map entries.
					 */
					distance = mapp - mapent;
					tmp = realloc(mapent,
						      ((MAPENT_MAX_LEN + 1) * 
						       ++alloci));
					if (!tmp) {
						alloci--;
						logerr(MODPREFIX "realloc: %s",
						      strerror(errno));
						break;
					}
					mapent = tmp;
					mapp = tmp + distance;
				}
				/* 
				 * Eat \ quoting \n, otherwise pass it
				 * through for the parser
				 */
				if (quoted) {
					if (ch == '\n')
						*mapp++ = ' ';
					else {
						*mapp++ = '\\';
						*mapp++ = ch;
					}
				} else
					*mapp++ = ch;
				break;
			case st_done:
				/* Eat characters till there's no more output */
				break;
			}
			quoted = 0;
			goto cont;
		}
		quoted = 0;
next:
		/* Deal with stderr */
		if (pfd[1].revents) {
			while (1) {
				bytes = read(epipefd[0], &ch, 1);
				if (bytes == 0)
					break;
				else if (bytes < 0) {
					pfd[1].fd = -1;
					break;
				} else if (ch == '\n') {
					*errp = '\0';
					if (errbuf[0])
						logmsg(">> %s", errbuf);
					errp = errbuf;
				} else {
					if (errp >= &errbuf[1023]) {
						*errp = '\0';
						logmsg(">> %s", errbuf);
						errp = errbuf;
					}
					*(errp++) = ch;
				}
			}
		}
	}

	if (mapp)
		*mapp = '\0';
	if (errp > errbuf) {
		*errp = '\0';
		logmsg(">> %s", errbuf);
	}

	close(pipefd[0]);
	close(epipefd[0]);

	if (waitpid(f, &status, 0) != f) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "waitpid: %s", estr);
		goto out_error;
	}

	if (mapp == mapent || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		info(ap->logopt, MODPREFIX "lookup for %s failed", name);
		goto out_error;
	}

	return mapent;

out_error:
	if (mapent)
		free(mapent);

	return NULL;
}

static int lookup_amd_defaults(struct autofs_point *ap,
			       struct map_source *source,
			       struct lookup_context *ctxt)
{
	struct mapent_cache *mc = source->mc;
	char *ment = lookup_one(ap, "/defaults", 9, ctxt);
	if (ment) {
		char *start = ment + 9;
		int ret;

		while (isblank(*start))
			start++;
		cache_writelock(mc);
		ret = cache_update(mc, source, "/defaults", start, monotonic_time(NULL));
		cache_unlock(mc);
		if (ret == CHE_FAIL) {
			free(ment);
			return NSS_STATUS_UNAVAIL;
		}
		free(ment);
	}
	return NSS_STATUS_SUCCESS;
}

static int match_key(struct autofs_point *ap,
		     struct map_source *source,
		     const char *name, int name_len,
		     char **mapent, struct lookup_context *ctxt)
{
	unsigned int is_amd_format = source->flags & MAP_FLAG_FORMAT_AMD;
	struct mapent_cache *mc = source->mc;
	char buf[MAX_ERR_BUF];
	char *ment;
	char *lkp_key;
	size_t lkp_len;
	char *prefix;
	int ret;

	if (is_amd_format) {
		ret = lookup_amd_defaults(ap, source, ctxt);
		if (ret != NSS_STATUS_SUCCESS) {
			warn(ap->logopt,
			     MODPREFIX "failed to save /defaults entry");
		}
	}

	if (!is_amd_format) {
		lkp_key = strdup(name);
		if (!lkp_key) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "malloc: %s", estr);
			return NSS_STATUS_UNAVAIL;
		}
		lkp_len = name_len;
	} else {
		size_t len;

		if (ap->pref)
			len = strlen(ap->pref) + strlen(name);
		else
			len = strlen(name);

		lkp_key = malloc(len + 1);
		if (!lkp_key) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "malloc: %s", estr);
			return NSS_STATUS_UNAVAIL;
		}

		if (ap->pref) {
			strcpy(lkp_key, ap->pref);
			strcat(lkp_key, name);
		} else
			strcpy(lkp_key, name);

		lkp_len = len;
	}

	ment = lookup_one(ap, lkp_key, lkp_len, ctxt);
	if (ment) {
		char *start = ment;
		if (is_amd_format) {
			start = ment + lkp_len;
			while (isblank(*start))
				start++;
		}
		cache_writelock(mc);
		ret = cache_update(mc, source, lkp_key, start, monotonic_time(NULL));
		cache_unlock(mc);
		if (ret == CHE_FAIL) {
			free(ment);
			free(lkp_key);
			return NSS_STATUS_UNAVAIL;
		}
		*mapent = strdup(start);
		if (!*mapent) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "malloc: %s", estr);
			free(lkp_key);
			free(ment);
			return NSS_STATUS_UNAVAIL;
		}
		free(lkp_key);
		free(ment);
		return NSS_STATUS_SUCCESS;
	}

	if (!is_amd_format) {
		free(lkp_key);
		return NSS_STATUS_NOTFOUND;
	}

	ret = NSS_STATUS_NOTFOUND;

	/*
	 * Now strip successive directory components and try a
	 * match against map entries ending with a wildcard and
	 * finally try the wilcard entry itself.
	 */
	while ((prefix = strrchr(lkp_key, '/'))) {
		char *match;
		size_t len;
		*prefix = '\0';
		len = strlen(lkp_key) + 3;
		match = malloc(len);
		if (!match) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "malloc: %s", estr);
			free(lkp_key);
			return NSS_STATUS_UNAVAIL;
		}
		len--;
		strcpy(match, lkp_key);
		strcat(match, "/*");
		ment = lookup_one(ap, match, len, ctxt);
		if (ment) {
			char *start = ment + len;
			while (isblank(*start))
				start++;
			cache_writelock(mc);
			ret = cache_update(mc, source, match, start, monotonic_time(NULL));
			cache_unlock(mc);
			if (ret == CHE_FAIL) {
				free(match);
				free(ment);
				free(lkp_key);
				return NSS_STATUS_UNAVAIL;
			}
			free(match);
			*mapent = strdup(start);
			if (!*mapent) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				error(ap->logopt, MODPREFIX "malloc: %s", estr);
				free(ment);
				free(lkp_key);
				return NSS_STATUS_UNAVAIL;
			}
			free(ment);
			free(lkp_key);
			return NSS_STATUS_SUCCESS;
		}
		free(match);
	}
	free(lkp_key);

	return ret;
}

int lookup_program_mount(struct autofs_point *ap, struct map_source *map, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source = map;
	struct mapent_cache *mc = source->mc;
	char *mapent = NULL;
	struct mapent *me;
	int ret = 1;

	/* Check if we recorded a mount fail for this key anywhere */
	me = lookup_source_mapent(ap, name, LKP_DISTINCT);
	if (me) {
		/* negative timeout has not passed, return fail */
		if (cache_lookup_negative(me, name) == CHE_UNAVAIL)
			return NSS_STATUS_NOTFOUND;
	}

	/* Catch installed direct offset triggers */
	cache_readlock(mc);
	me = cache_lookup_distinct(mc, name);
	if (!me) {
		cache_unlock(mc);
		/*
		 * If there's a '/' in the name and the offset is not in
		 * the cache then it's not a valid path in the mount tree.
		 */
		if (strchr(name, '/')) {
			debug(ap->logopt,
			      MODPREFIX "offset %s not found", name);
			return NSS_STATUS_NOTFOUND;
		}
	} else {
		/* Otherwise we found a valid offset so try mount it */
		debug(ap->logopt, MODPREFIX "%s -> %s", name, me->mapent);

		/*
		 * If this is a request for an offset mount (whose entry
		 * must be present in the cache to be valid) or the entry
		 * is newer than the negative timeout value then just
		 * try and mount it. Otherwise try and remove it and
		 * proceed with the program map lookup.
		 */
		if (strchr(name, '/') ||
		    me->age + ap->negative_timeout > monotonic_time(NULL)) {
			char *ent = NULL;

			if (me->mapent) {
				ent = malloc(strlen(me->mapent) + 1);
				if (!ent) {
					char buf[MAX_ERR_BUF];
					char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error(ap->logopt, MODPREFIX "malloc: %s", estr);
					cache_unlock(mc);
					goto out_free;
				}
				strcpy(ent, me->mapent);
			}
			cache_unlock(mc);
			ret = ctxt->parse->parse_mount(ap, source,
						       name, name_len, ent,
						       ctxt->parse->context);
			if (ent)
				free(ent);
			goto out_free;
		} else {
			if (IS_MM(me) && !IS_MM_ROOT(me)) {
				cache_unlock(mc);
				warn(ap->logopt, MODPREFIX
				     "unexpected lookup for active multi-mount"
				     " key %s, returning fail", name);
				return NSS_STATUS_UNAVAIL;
			}
			cache_unlock(mc);
			cache_writelock(mc);
			me = cache_lookup_distinct(mc, name);
			if (me) {
				if (IS_MM(me))
					tree_mapent_delete_offsets(mc, name);
				cache_delete(mc, name);
			}
			cache_unlock(mc);
		}
	}

	debug(ap->logopt, MODPREFIX "looking up %s", name);

	ret = match_key(ap, source, name, name_len, &mapent, ctxt);
	if (ret != NSS_STATUS_SUCCESS)
		goto out_free;

	debug(ap->logopt, MODPREFIX "%s -> %s", name, mapent);

	ret = ctxt->parse->parse_mount(ap, source, name, name_len,
				       mapent, ctxt->parse->context);
out_free:
	if (mapent)
		free(mapent);

	if (ret) {
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

int lookup_program_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	if (ctxt->mapfmt)
		free(ctxt->mapfmt);
	free(ctxt);
	return rv;
}
