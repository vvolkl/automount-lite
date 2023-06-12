/* ----------------------------------------------------------------------- *
 *
 *  lookup_sss.c - module for Linux automount to query sss service
 *
 *   Copyright 2012 Ian Kent <raven@themaw.net>
 *   Copyright 2012 Red Hat, Inc.
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
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

/* One second between retries */
#define SSS_WAIT_INTERVAL	1

#define MODPREFIX "lookup(sss): "

#define SSS_SO_NAME "libsss_autofs"

/* If the sss library protocol version is greater than 0 there are
 * more possibile error returns from the sss autofs library calls.
 *
 * If ECONNREFUSED is returned then sssd is not running or not
 * configured on the system, immediately return an unavailable
 * status.
 *
 * A return of EHOSTDOWN means sss backend server is down so we
 * should retry.
 *
 * With older sss ilibrary we can get a return of ENOENT for the
 * above cases so also wait in that case since we can't be sure
 * the map doesn't exist.
 */
#define SSS_PROTO_VERSION 1

#define SSS_DEFAULT_WAIT	10

/* When the master map is being read a retry loop is used by the
 * caller to try harder to read the master map because it is required
 * for autofs to start up.
 *
 * But when reading dependent maps or looking up a key that loop isn't
 * used so a longer retry is needed for those cases.
 *
 * Introduce a flag to indicate which map is being read or if a lookup
 * is being done so the number of retries can be adjusted accordingly.
 */
#define SSS_READ_NONE		0x00
#define SSS_READ_MASTER_MAP	0x01
#define SSS_REREAD_MASTER_MAP	0x02
#define SSS_READ_DEPENDENT_MAP	0x04
#define SSS_LOOKUP_KEY		0x08

unsigned int _sss_auto_protocol_version(unsigned int);
int _sss_setautomntent(const char *, void **);
int _sss_getautomntent_r(char **, char **, void *);
int _sss_getautomntbyname_r(char *, char **, void *);
int _sss_endautomntent(void **);

typedef unsigned int (*protocol_version_t) (unsigned int);
typedef int (*setautomntent_t) (const char *, void **);
typedef int (*getautomntent_t) (char **, char **, void *);
typedef int (*getautomntbyname_t) (char *, char **, void *);
typedef int (*endautomntent_t) (void **);

struct lookup_context {
	const char *mapname;
    	void *dlhandle;
	protocol_version_t protocol_version;
	setautomntent_t setautomntent;
	getautomntent_t getautomntent_r;
	getautomntbyname_t getautomntbyname_r;
	endautomntent_t endautomntent;
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */
int sss_proto_version = SSS_PROTO_VERSION;	/* 0 => initial version,
						 * >= 1 => new error handling. */

static int open_sss_lib(struct lookup_context *ctxt)
{
	char dlbuf[PATH_MAX];
	char *estr;
	void *dh;
	size_t size;

	size = snprintf(dlbuf, sizeof(dlbuf),
			"%s/%s.so", SSS_LIB_DIR, SSS_SO_NAME);
	if (size >= sizeof(dlbuf)) {
		logmsg(MODPREFIX "sss library path too long");
		return 1;
	}

	dh = dlopen(dlbuf, RTLD_LAZY);
	if (!dh)
		return 1;
	ctxt->dlhandle = dh;

	/* Don't fail on NULL, it's simply not present in this version of the
	 * sss autofs library.
	 */
	ctxt->protocol_version = (protocol_version_t) dlsym(dh, "_sss_auto_protocol_version");

	ctxt->setautomntent = (setautomntent_t) dlsym(dh, "_sss_setautomntent");
	if (!ctxt->setautomntent)
		goto lib_names_fail;

	ctxt->getautomntent_r = (getautomntent_t) dlsym(dh, "_sss_getautomntent_r");
	if (!ctxt->getautomntent_r)
		goto lib_names_fail;

	ctxt->getautomntbyname_r = (getautomntbyname_t) dlsym(dh, "_sss_getautomntbyname_r");
	if (!ctxt->getautomntbyname_r)
		goto lib_names_fail;

	ctxt->endautomntent = (endautomntent_t) dlsym(dh, "_sss_endautomntent");
	if (!ctxt->endautomntent)
		goto lib_names_fail;

	return 0;

lib_names_fail:
	if ((estr = dlerror()) == NULL)
		logmsg(MODPREFIX "failed to locate sss library entry points");
	else
		logerr(MODPREFIX "dlsym: %s", estr);
	dlclose(dh);

	return 1;
}

static int do_init(const char *mapfmt,
		   int argc, const char *const *argv,
		   struct lookup_context *ctxt, unsigned int reinit)
{
	int ret = 0;

	if (argc < 1) {
		logerr(MODPREFIX "No map name");
		ret = 1;
		goto out;
	}
	ctxt->mapname = argv[0];

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	if (!reinit) {
		ret = open_sss_lib(ctxt);
		if (ret)
			goto out;
	}

	if (reinit) {
		ret = reinit_parse(ctxt->parse, mapfmt, MODPREFIX, argc - 1, argv + 1);
		if (ret)
			logmsg(MODPREFIX "failed to reinit parse context");
	} else {
		ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
		if (!ctxt->parse) {
			logmsg(MODPREFIX "failed to open parse context");
			dlclose(ctxt->dlhandle);
			ret = 1;
		}
	}
out:
	return ret;
}

int lookup_init(const char *mapfmt,
		int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];
	char *estr;

	*context = NULL;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	if (do_init(mapfmt, argc, argv, ctxt, 0)) {
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
	struct lookup_context *new;
	char buf[MAX_ERR_BUF];
	int ret;

	new = malloc(sizeof(struct lookup_context));
	if (!new) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	new->parse = ctxt->parse;
	ret = do_init(mapfmt, argc, argv, new, 1);
	if (ret) {
		free(new);
		return 1;
	}

	new->dlhandle = ctxt->dlhandle;
	new->protocol_version = ctxt->protocol_version;
	new->setautomntent = ctxt->setautomntent;
	new->getautomntent_r = ctxt->getautomntent_r;
	new->getautomntbyname_r = ctxt->getautomntbyname_r;
	new->endautomntent = ctxt->endautomntent;

	*context = new;

	free(ctxt);

	return 0;
}

static unsigned int proto_version(struct lookup_context *ctxt)
{
	unsigned int proto_version = 0;

	if (ctxt->protocol_version) {
		/* If ctxt->protocol_version() is defined it's assumed
		 * that for sss_proto_version <= sss autofs library
		 * protocol version ctxt->protocol_version() will
		 * return the version requested by autofs to indicate
		 * it userstands what the autofs module is capable of
		 * handling.
		 */
		proto_version = ctxt->protocol_version(sss_proto_version);
	}
	return proto_version;
}

static unsigned int calculate_retry_count(struct lookup_context *ctxt, unsigned int flags)
{
	int retries;

	retries = defaults_get_sss_master_map_wait();

	/* If sss_master_map_wait is not set in the autofs
	 * configuration give it a sensible value since we
	 * want to wait for a host that's down in case it
	 * comes back up.
	 *
	 * Use the sss_master_map_wait configuration option
	 * for the time to wait when reading a dependednt map
	 * or performing a key lookup too.
	 */
	if (retries <= 0) {
		/* Protocol version 0 cant't tell us about
		 * a host being down, return 0 for retries.
		 */
		if (proto_version(ctxt) == 0)
			return 0;
		else
			retries = SSS_DEFAULT_WAIT;
	}

	if (proto_version(ctxt) == 0)
		return retries;

	/* When the master map is being read there's an additional
	 * outer wait loop.
	 *
	 * If master map wait is set in the configuration there
	 * will be an outer loop interating master_map_wait / 2
	 * times so adjust the number of retries here to account
	 * for this for the cases where the master map isn't being
	 * read.
	 */

	if (!(flags & SSS_READ_MASTER_MAP) ||
	     (flags & SSS_REREAD_MASTER_MAP)) {
		unsigned int master_map_wait = defaults_get_master_wait();
		unsigned int m_wait;

		m_wait = master_map_wait ? master_map_wait : SSS_DEFAULT_WAIT;
		retries *= (m_wait / 2);
	}

	return retries;
}

static int setautomntent_wait(unsigned int logopt,
			      struct lookup_context *ctxt, void **sss_ctxt,
			      unsigned int flags)
{
	unsigned int retries;
	unsigned int retry = 0;
	int ret = 0;

	*sss_ctxt = NULL;

	retries = calculate_retry_count(ctxt, flags);
	if (retries == 0) {
		if (proto_version(ctxt) == 0)
			return EINVAL;
		return ENOENT;
	}

	warn(logopt,
	     "can't connect to sssd, retry for %d seconds",
	     retries);

	while (++retry < retries) {
		struct timespec t = { SSS_WAIT_INTERVAL, 0 };
		struct timespec r;

		while (nanosleep(&t, &r) == -1 && errno == EINTR)
			memcpy(&t, &r, sizeof(struct timespec));

		ret = ctxt->setautomntent(ctxt->mapname, sss_ctxt);
		if (proto_version(ctxt) == 0) {
			if (ret != ENOENT)
				break;
		} else {
			if (ret != EHOSTDOWN)
				break;
		}

		if (*sss_ctxt) {
			free(*sss_ctxt);
			*sss_ctxt = NULL;
		}
	}

	if (!ret)
		info(logopt, "successfully connected to sssd");
	else {
		if (*sss_ctxt) {
			free(*sss_ctxt);
			*sss_ctxt = NULL;
		}

		if (proto_version(ctxt) == 0 && retry >= retries)
			ret = ETIMEDOUT;
	}
	return ret;
}

static int setautomntent(unsigned int logopt,
			 struct lookup_context *ctxt, void **sss_ctxt,
			 unsigned int flags)
{
	char buf[MAX_ERR_BUF];
	char *estr;
	int err = NSS_STATUS_UNAVAIL;
	int ret;

	ret = ctxt->setautomntent(ctxt->mapname, sss_ctxt);
	if (ret) {
		if (ret == ECONNREFUSED) {
			err = NSS_STATUS_UNKNOWN;
			goto error;
		}

		if (proto_version(ctxt) == 0) {
			if (ret != ENOENT)
				goto error;
		} else {
			/* If we get an ENOENT here assume it's accurrate
			 * and return the error.
			 */
			if (ret == ENOENT) {
				error(logopt, MODPREFIX
				      "setautomountent: entry for map %s not found",
				      ctxt->mapname);
				err = NSS_STATUS_NOTFOUND;
				goto free;
			}
			if (ret != EHOSTDOWN)
				goto error;
		}

		ret = setautomntent_wait(logopt, ctxt, sss_ctxt, flags);
		if (ret) {
			if (ret == ECONNREFUSED) {
				err = NSS_STATUS_UNKNOWN;
				goto error;
			}
			if (ret == ETIMEDOUT)
				goto error;
			/* sss proto version 0 and sss timeout not set */
			if (ret == EINVAL)
				goto free;
			if (ret == ENOENT) {
				/* Map info. not found after host became available */
				error(logopt, MODPREFIX
				      "setautomountent: entry for map %s not found",
				      ctxt->mapname);
				err = NSS_STATUS_NOTFOUND;
				goto free;
			}
			goto error;
		}
	}
	return NSS_STATUS_SUCCESS;

error:
	estr = strerror_r(ret, buf, MAX_ERR_BUF);
	error(logopt, MODPREFIX "setautomntent: %s", estr);
free:
	if (*sss_ctxt) {
		free(*sss_ctxt);
		*sss_ctxt = NULL;
	}
	return err;
}

static int endautomntent(unsigned int logopt,
			 struct lookup_context *ctxt, void **sss_ctxt)
{
	int ret = ctxt->endautomntent(sss_ctxt);
	if (ret) {
		char buf[MAX_ERR_BUF];
		char *estr = strerror_r(ret, buf, MAX_ERR_BUF);
		error(logopt, MODPREFIX "endautomntent: %s", estr);
	}
	return ret;
}

static int getautomntent_wait(unsigned int logopt,
			 struct lookup_context *ctxt,
			 char **key, char **value, void *sss_ctxt,
			 unsigned int flags)
{
	unsigned int retries;
	unsigned int retry = 0;
	int ret = 0;

	retries = calculate_retry_count(ctxt, flags);
	if (retries == 0) {
		if (proto_version(ctxt) == 0)
			return EINVAL;
		return ENOENT;
	}

	warn(logopt,
	 "can't contact sssd to to get map entry, retry for %d seconds",
	 retries);

	while (++retry < retries) {
		struct timespec t = { SSS_WAIT_INTERVAL, 0 };
		struct timespec r;

		while (nanosleep(&t, &r) == -1 && errno == EINTR)
			memcpy(&t, &r, sizeof(struct timespec));

		ret = ctxt->getautomntent_r(key, value, sss_ctxt);
		if (proto_version(ctxt) == 0) {
			if (ret != ENOENT)
				break;
		} else {
			if (ret != EHOSTDOWN)
				break;
		}
	}

	if (!ret)
		info(logopt,
		     "successfully contacted sssd to get map entry");
	else {
		if (proto_version(ctxt) == 0 && retry >= retries)
			ret = ETIMEDOUT;
	}
	return ret;
}

static int getautomntent(unsigned int logopt,
			 struct lookup_context *ctxt,
			 char **key, char **value, int count,
			 void *sss_ctxt, unsigned int flags)
{
	char buf[MAX_ERR_BUF];
	char *estr;
	int err = NSS_STATUS_UNAVAIL;
	int ret;

	ret = ctxt->getautomntent_r(key, value, sss_ctxt);
	if (ret) {
		/* Host has gone down */
		if (ret == ECONNREFUSED) {
			err = NSS_STATUS_UNKNOWN;
			goto error;
		}

		if (proto_version(ctxt) == 0) {
			if (ret != ENOENT)
				goto error;
			/* For prorocol version 0 ENOENT can only be
			 * used to indicate we've read all entries.
			 * So even if we haven't got any values yet we
			 * can't use it to determine if we need to wait
			 * on sss.
			 */
			err = NSS_STATUS_NOTFOUND;
			if (count)
				err = NSS_STATUS_SUCCESS;
			goto free;
		} else {
			if (ret == ENOENT) {
				err = NSS_STATUS_NOTFOUND;
				if (count)
					err = NSS_STATUS_SUCCESS;
				goto free;
			}
			if (ret != EHOSTDOWN)
				goto error;
		}

		ret = getautomntent_wait(logopt, ctxt,
					 key, value, sss_ctxt, flags);
		if (ret) {
			if (ret == ECONNREFUSED) {
				err = NSS_STATUS_UNKNOWN;
				goto free;
			}
			if (ret == ETIMEDOUT)
				goto error;
			/* sss proto version 0 and sss timeout not set => EINVAL */
			if (ret == ENOENT || ret == EINVAL) {
				err = NSS_STATUS_NOTFOUND;
				if (count)
					err = NSS_STATUS_SUCCESS;
				goto free;
			}
			goto error;
		}
	}
	return NSS_STATUS_SUCCESS;

error:
	estr = strerror_r(ret, buf, MAX_ERR_BUF);
	error(logopt, MODPREFIX "getautomntent: %s", estr);
free:
	if (*key) {
		free(*key);
		*key = NULL;
	}
	if (*value) {
		free(*value);
		*value = NULL;
	}
	return err;
}

static int getautomntbyname_wait(unsigned int logopt,
			 struct lookup_context *ctxt,
			 char *key, char **value, void *sss_ctxt,
			 unsigned int flags)
{
	unsigned int retries;
	unsigned int retry = 0;
	int ret = 0;

	retries = calculate_retry_count(ctxt, flags);
	if (retries == 0) {
		if (proto_version(ctxt) == 0)
			return EINVAL;
		return ENOENT;
	}

	warn(logopt,
	"can't contact sssd to to lookup key value, retry for %d seconds",
	retries);

	while (++retry < retries) {
		struct timespec t = { SSS_WAIT_INTERVAL, 0 };
		struct timespec r;

		while (nanosleep(&t, &r) == -1 && errno == EINTR)
			memcpy(&t, &r, sizeof(struct timespec));

		ret = ctxt->getautomntbyname_r(key, value, sss_ctxt);
		if (proto_version(ctxt) == 0) {
			if (ret != ENOENT)
				break;
		} else {
			if (ret != EHOSTDOWN)
				break;
		}
	}

	if (!ret)
		info(logopt,
		     "successfully contacted sssd to lookup key value");
	else {
		if (proto_version(ctxt) == 0 && retry >= retries)
			ret = ETIMEDOUT;
	}
	return ret;
}

static int getautomntbyname(unsigned int logopt,
			    struct lookup_context *ctxt,
			    char *key, char **value, void *sss_ctxt,
			    unsigned int flags)
{
	char buf[MAX_ERR_BUF];
	char *estr;
	int err = NSS_STATUS_UNAVAIL;
	int ret;

	ret = ctxt->getautomntbyname_r(key, value, sss_ctxt);
	if (ret) {
		/* Host has gone down */
		if (ret == ECONNREFUSED)
			goto error;

		if (proto_version(ctxt) == 0) {
			if (ret != ENOENT)
				goto error;
			/* For prorocol version 0 ENOENT can only be
			 * used to indicate no entry was found. So it
			 * can't be used to determine if we need to wait
			 * on sss.
			 */
			err = NSS_STATUS_NOTFOUND;
			goto free;
		} else {
			if (ret == ENOENT) {
				err = NSS_STATUS_NOTFOUND;
				goto free;
			}
			if (ret != EHOSTDOWN)
				goto error;
		}

		ret = getautomntbyname_wait(logopt, ctxt,
					    key, value, sss_ctxt, flags);
		if (ret) {
			if (ret == ECONNREFUSED)
				goto free;
			if (ret == ETIMEDOUT)
				goto error;
			/* sss proto version 0 and sss timeout not set */
			if (ret == EINVAL)
				goto free;
			if (ret == ENOENT) {
				err = NSS_STATUS_NOTFOUND;
				goto free;
			}
			goto error;
		}
	}
	return NSS_STATUS_SUCCESS;

error:
	estr = strerror_r(ret, buf, MAX_ERR_BUF);
	error(logopt, MODPREFIX "getautomntbyname: %s", estr);
free:
	if (*value) {
		free(*value);
		*value = NULL;
	}
	return err;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	unsigned int timeout = master->default_timeout;
	unsigned int logging = master->default_logging;
	unsigned int logopt = master->logopt;
	void *sss_ctxt = NULL;
	char buf[MAX_ERR_BUF];
	char *buffer;
	size_t buffer_len;
	char *key;
	char *value = NULL;
	int count, ret;
	unsigned int flags;

	flags = SSS_READ_MASTER_MAP;
	if (master->readall)
		flags |= SSS_REREAD_MASTER_MAP;

	ret = setautomntent(logopt, ctxt, &sss_ctxt, flags);
	if (ret)
		return ret;

	count = 0;
	while (1) {
	        key = NULL;
	        value = NULL;
		ret = getautomntent(logopt, ctxt,
				    &key, &value, count,
				    sss_ctxt, SSS_READ_MASTER_MAP);
		if (ret) {
			endautomntent(logopt, ctxt, &sss_ctxt);
			return ret;
		}

		if (!key || !value)
			break;

		count++;

		buffer_len = strlen(key) + 1 + strlen(value) + 2;
		buffer = malloc(buffer_len);
		if (!buffer) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(logopt, MODPREFIX "malloc: %s", estr);
			endautomntent(logopt, ctxt, &sss_ctxt);
			free(key);
			free(value);
			return NSS_STATUS_UNAVAIL;
		}

		/*
		 * TODO: implement sun % hack for key translation for
		 * mixed case keys in schema that are single case only.
		 */

		strcpy(buffer, key);
		strcat(buffer, " ");
		strcat(buffer, value);

		/*
		 * TODO: handle cancelation. This almost certainly isn't
		 * handled properly by other lookup modules either so it
		 * should be done when cancelation is reviewed for the
		 * other modules. Ditto for the other lookup module entry
		 * points.
		 */
		master_parse_entry(buffer, timeout, logging, age);

		free(buffer);
		free(key);
		free(value);
	}

	endautomntent(logopt, ctxt, &sss_ctxt);

	return NSS_STATUS_SUCCESS;
}

int lookup_read_map(struct autofs_point *ap, struct map_source *map, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source = map;
	struct mapent_cache *mc = source->mc;
	void *sss_ctxt = NULL;
	char *key;
	char *value = NULL;
	char *s_key;
	int count, ret;

	/*
	 * If we don't need to create directories (or don't need
	 * to read an amd cache:=all map) then there's no use
	 * reading the map. We always need to read the whole map
	 * for direct mounts in order to mount the triggers.
	 */
	if (ap->type != LKP_DIRECT &&
	    !(ap->flags & (MOUNT_FLAG_GHOST|MOUNT_FLAG_AMD_CACHE_ALL))) {
		debug(ap->logopt, "map read not needed, so not done");
		return NSS_STATUS_SUCCESS;
	}

	ret = setautomntent(ap->logopt, ctxt,
			    &sss_ctxt, SSS_READ_DEPENDENT_MAP);
	if (ret)
		return ret;

	count = 0;
	while (1) {
	        key = NULL;
	        value = NULL;
		ret = getautomntent(ap->logopt, ctxt,
				    &key, &value, count,
				    sss_ctxt, SSS_READ_DEPENDENT_MAP);
		if (ret) {
			endautomntent(ap->logopt, ctxt, &sss_ctxt);
			return ret;
		}

		if (!key || !value)
			break;

		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (*key == '+') {
			warn(ap->logopt,
			     MODPREFIX "ignoring '+' map entry - not in file map");
			free(key);
			free(value);
			continue;
		}

		if (*key == '/' && strlen(key) == 1) {
			if (ap->type == LKP_DIRECT) {
				free(key);
				free(value);
				continue;
			}
			*key = '*';
		}

		/*
		 * TODO: implement sun % hack for key translation for
		 * mixed case keys in schema that are single case only.
		 */

		s_key = sanitize_path(key, strlen(key), ap->type, ap->logopt);
		if (!s_key) {
			error(ap->logopt, MODPREFIX "invalid path %s", key);
			endautomntent(ap->logopt, ctxt, &sss_ctxt);
			free(key);
			free(value);
			return NSS_STATUS_NOTFOUND;
		}

		count++;

		cache_writelock(mc);
		cache_update(mc, source, s_key, value, age);
		cache_unlock(mc);

		free(s_key);
		free(key);
		free(value);
	}

	endautomntent(ap->logopt, ctxt, &sss_ctxt);

	source->age = age;

	return NSS_STATUS_SUCCESS;
}

static int lookup_one(struct autofs_point *ap, struct map_source *source,
		      char *qKey, int qKey_len, struct lookup_context *ctxt)
{
	struct mapent_cache *mc = source->mc;
	struct mapent *we;
	void *sss_ctxt = NULL;
	time_t age = monotonic_time(NULL);
	char *value = NULL;
	char *s_key;
	int err, ret;

	ret = setautomntent(ap->logopt, ctxt, &sss_ctxt, SSS_LOOKUP_KEY);
	if (ret)
		return ret;

	ret = getautomntbyname(ap->logopt, ctxt,
			       qKey, &value, sss_ctxt, SSS_LOOKUP_KEY);
	if (ret == NSS_STATUS_NOTFOUND)
		goto wild;
	if (ret) {
		endautomntent(ap->logopt, ctxt, &sss_ctxt);
		return ret;
	}

	/*
	 * TODO: implement sun % hack for key translation for
	 * mixed case keys in schema that are single case only.
	 */
	s_key = sanitize_path(qKey, qKey_len, ap->type, ap->logopt);
	if (!s_key) {
		free(value);
		value = NULL;
		goto wild;
	}
	cache_writelock(mc);
	err = cache_update(mc, source, s_key, value, age);
	cache_unlock(mc);
	/* Entry in map but not in cache, map is stale */
	if (err & CHE_UPDATED)
		source->stale = 1;
	endautomntent(ap->logopt, ctxt, &sss_ctxt);
	free(s_key);
	free(value);
	return NSS_STATUS_SUCCESS;

wild:
	ret = getautomntbyname(ap->logopt, ctxt,
			       "/", &value, sss_ctxt, SSS_LOOKUP_KEY);
	if (ret) {
		if (ret != NSS_STATUS_NOTFOUND) {
			endautomntent(ap->logopt, ctxt, &sss_ctxt);
			return ret;
		}
		ret = getautomntbyname(ap->logopt, ctxt,
				       "*", &value, sss_ctxt, SSS_LOOKUP_KEY);
		if (ret && ret != NSS_STATUS_NOTFOUND) {
			endautomntent(ap->logopt, ctxt, &sss_ctxt);
			return ret;
		}
	}

	if (ret == NSS_STATUS_NOTFOUND) {
		/* Failed to find wild entry, update cache if needed */
		cache_writelock(mc);
		we = cache_lookup_distinct(mc, "*");
		if (we) {
			/* Wildcard entry existed and is now gone */
			if (we->source == source) {
				cache_delete(mc, "*");
				source->stale = 1;
			}
		}

		/* Not found in the map but found in the cache */
		struct mapent *exists = cache_lookup_distinct(mc, qKey);
		if (exists && exists->source == source) {
			if (exists->mapent) {
				free(exists->mapent);
				exists->mapent = NULL;
				source->stale = 1;
				exists->status = 0;
			}
		}
		cache_unlock(mc);
		endautomntent(ap->logopt, ctxt, &sss_ctxt);
		return NSS_STATUS_NOTFOUND;
	}

	cache_writelock(mc);
	/* Wildcard in map but not in cache, update it */
	err = cache_update(mc, source, "*", value, age);
	cache_unlock(mc);
	/* Wildcard in map but not in cache, map is stale */
	if (err & CHE_UPDATED)
		source->stale = 1;

	endautomntent(ap->logopt, ctxt, &sss_ctxt);
        free(value);

	return NSS_STATUS_SUCCESS;
}

static int check_map_indirect(struct autofs_point *ap,
			      struct map_source *source, char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct mapent_cache *mc = source->mc;
	int ret, cur_state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	ret = lookup_one(ap, source, key, key_len, ctxt);
	if (ret == NSS_STATUS_NOTFOUND) {
		pthread_setcancelstate(cur_state, NULL);
		return ret;
	} else if (ret == NSS_STATUS_UNAVAIL) {
		/*
		 * If the server is down and the entry exists in the cache
		 * and belongs to this map return success and use the entry.
		 */
		struct mapent *exists = cache_lookup(mc, key);
		if (exists && exists->source == source) {
			pthread_setcancelstate(cur_state, NULL);
			return NSS_STATUS_SUCCESS;
		}
		pthread_setcancelstate(cur_state, NULL);

		warn(ap->logopt,
		     MODPREFIX "lookup for %s failed: connection failed", key);

		return ret;
	}
	pthread_setcancelstate(cur_state, NULL);

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, struct map_source *map, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source = map;
	struct mapent_cache *mc = source->mc;
	struct mapent *me;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	char mapent_buf[MAPENT_MAX_LEN + 1];
	int ret;

	debug(ap->logopt, MODPREFIX "looking up %s", name);

	key_len = snprintf(key, KEY_MAX_LEN + 1, "%s", name);
	if (key_len > KEY_MAX_LEN)
		return NSS_STATUS_NOTFOUND;

	/* Check if we recorded a mount fail for this key anywhere */
	me = lookup_source_mapent(ap, key, LKP_DISTINCT);
	if (me) {
		/* negative timeout has not passed, return fail */
		if (cache_lookup_negative(me, key) == CHE_UNAVAIL)
			return NSS_STATUS_NOTFOUND;
	}

        /*
	 * We can't check the direct mount map as if it's not in
	 * the map cache already we never get a mount lookup, so
	 * we never know about it.
	 */
	if (ap->type == LKP_INDIRECT && *key != '/') {
		int status;
		char *lkp_key;

		cache_readlock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me && IS_MM(me))
			lkp_key = strdup(MM_ROOT(me)->key);
		else
			lkp_key = strdup(key);
		cache_unlock(mc);

		if (!lkp_key)
			return NSS_STATUS_UNKNOWN;

		status = check_map_indirect(ap, source, lkp_key, strlen(lkp_key), ctxt);
		free(lkp_key);
		if (status)
			return status;
	}

	/*
	 * We can't take the writelock for direct mounts. If we're
	 * starting up or trying to re-connect to an existing direct
	 * mount we could be iterating through the map entries with
	 * the readlock held. But we don't need to update the cache
	 * when we're starting up so just take the readlock in that
	 */
	if (ap->flags & MOUNT_FLAG_REMOUNT)
		cache_readlock(mc);
	else
		cache_writelock(mc);
	me = cache_lookup(mc, key);
	/* Stale mapent => check for entry in alternate source or wildcard */
	if (me && !me->mapent) {
		while ((me = cache_lookup_key_next(me)))
			if (me->source == source)
				break;
		if (!me)
			me = cache_lookup_distinct(mc, "*");
	}
	if (me && me->mapent) {
		/*
		 * If this is a lookup add wildcard match for later validation
		 * checks and negative cache lookups.
		 */
		if (ap->type == LKP_INDIRECT && *me->key == '*' &&
		   !(ap->flags & MOUNT_FLAG_REMOUNT)) {
			ret = cache_update(mc, source, key, me->mapent, me->age);
			if (!(ret & (CHE_OK | CHE_UPDATED)))
				me = NULL;
		}
		if (me && (me->source == source || *me->key == '/')) {
			strcpy(mapent_buf, me->mapent);
			mapent = mapent_buf;
		}
	}
	cache_unlock(mc);

	if (!mapent)
		return NSS_STATUS_TRYAGAIN;

	debug(ap->logopt, MODPREFIX "%s -> %s", key, mapent);

	ret = ctxt->parse->parse_mount(ap, source, key, key_len,
				       mapent, ctxt->parse->context);
	if (ret) {
		/* Don't update negative cache when re-connecting */
		if (ap->flags & MOUNT_FLAG_REMOUNT)
			return NSS_STATUS_TRYAGAIN;
		cache_writelock(mc);
		cache_update_negative(mc, source, key, ap->negative_timeout);
		cache_unlock(mc);
		return NSS_STATUS_TRYAGAIN;
	}

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	dlclose(ctxt->dlhandle);
	free(ctxt);
	return rv;
}
