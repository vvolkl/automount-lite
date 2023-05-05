/* ----------------------------------------------------------------------- *
 *
 *  mount_autofs.c - Module for recursive autofs mounts.
 *
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define MODULE_MOUNT
#include "automount.h"

#define MODPREFIX "mount(autofs): "

/* Attributes to create handle_mounts() thread */
extern pthread_attr_t th_attr;
extern struct startup_cond suc;

int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */

int mount_init(void **context)
{
	return 0;
}

int mount_reinit(void **context)
{
	return 0;
}

int mount_mount(struct autofs_point *ap, const char *root, const char *name,
		int name_len, const char *what, const char *fstype,
		const char *c_options, void *context)
{
	struct startup_cond suc;
	pthread_t thid;
	char mountpoint[PATH_MAX + 1];
	const char **argv;
	int argc, status;
	int nobind = ap->flags & MOUNT_FLAG_NOBIND;
	int ghost = ap->flags & MOUNT_FLAG_GHOST;
	int symlnk = ap->flags & MOUNT_FLAG_SYMLINK;
	int strictexpire = ap->flags & MOUNT_FLAG_STRICTEXPIRE;
	time_t timeout = get_exp_timeout(ap, ap->entry->maps);
	unsigned logopt = ap->logopt;
	struct map_type_info *info;
	struct master *master;
	struct master_mapent *entry;
	struct map_source *source;
	struct autofs_point *nap;
	struct mnt_list *mnt;
	char buf[MAX_ERR_BUF];
	char *options, *p;
	int err, ret;
	int hosts = 0;

	/* Root offset of multi-mount */
	if (root[strlen(root) - 1] == '/') {
		err = snprintf(mountpoint, PATH_MAX + 1, "%s", root);
		if (err > PATH_MAX) {
			error(ap->logopt, MODPREFIX "string too long for mountpoint");
			return 1;
		}
		mountpoint[err - 1] = 0;
	} else if (*name == '/') {
		if (ap->flags & MOUNT_FLAG_REMOUNT) {
			err = snprintf(mountpoint, PATH_MAX + 1, "%s", name);
			if (err > PATH_MAX) {
				error(ap->logopt, MODPREFIX "string too long for mountpoint");
				return 1;
			}
		} else {
			err = snprintf(mountpoint, PATH_MAX + 1, "%s", root);
			if (err > PATH_MAX) {
				error(ap->logopt, MODPREFIX "string too long for mountpoint");
				return 1;
			}
		}
	} else {
		err = snprintf(mountpoint, PATH_MAX + 1, "%s/%s", root, name);
		if (err > PATH_MAX) {
			error(ap->logopt, MODPREFIX "string too long for mountpoint");
			return 1;
		}
	}

	options = NULL;
	if (c_options) {
		char *noptions;
		const char *comma;
		char *np;
		int len = strlen(c_options) + 1;

		noptions = np = alloca(len);
		if (!np) {
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
			error(ap->logopt, MODPREFIX "alloca: %s", estr);
			return 1;
		}
		memset(np, 0, len);

		/* Grab the autofs specific options */
		for (comma = c_options; *comma != '\0';) {
			const char *cp;

			while (*comma == ',')
				comma++; 

			cp = comma;

			while (*comma != '\0' && *comma != ',')
				comma++;

			if (_strncmp("nobrowse", cp, 8) == 0 ||
			    _strncmp("nobrowsable", cp, 11) == 0)
				ghost = 0;
			else if (_strncmp("nobind", cp, 6) == 0)
				nobind = 1;
			else if (_strncmp("browse", cp, 6) == 0 ||
				 _strncmp("browsable", cp, 9) == 0)
				ghost = 1;
			else if (_strncmp("symlink", cp, 7) == 0)
				symlnk = 1;
			else if (_strncmp("strictexpire", cp, 12) == 0)
				strictexpire = 1;
			else if (_strncmp("hosts", cp, 5) == 0)
				hosts = 1;
			else if (_strncmp("timeout=", cp, 8) == 0) {
				char *val = strchr(cp, '=');
				unsigned tout;
				if (val) {
					int ret = sscanf(cp, "timeout=%u", &tout);
					if (ret)
						timeout = tout;
				}
			} else {
				memcpy(np, cp, comma - cp + 1);
				np += comma - cp + 1;
			}
		}
		options = noptions;
	}

	debug(ap->logopt,
	      MODPREFIX "mountpoint=%s what=%s options=%s",
	      mountpoint, what, options);

	master = ap->entry->master;

	entry = master_new_mapent(master, mountpoint, ap->entry->age);
	if (!entry) {
		error(ap->logopt,
		      MODPREFIX "failed to malloc master_mapent struct");
		return 1;
	}

	ret = master_add_autofs_point(entry, logopt, nobind, ghost, 1);
	if (!ret) {
		error(ap->logopt,
		      MODPREFIX "failed to add autofs_point to entry");
		master_free_mapent(entry);
		return 1;
	}
	nap = entry->ap;
	nap->parent = ap;
	if (symlnk)
		nap->flags |= MOUNT_FLAG_SYMLINK;
	if (strictexpire)
		nap->flags |= MOUNT_FLAG_STRICTEXPIRE;

	if (hosts)
		argc = 0;
	else
		argc = 1;

	if (options) {
		char *t = options;
		do {
			argc++;
			if (*t == ',')
				t++;
		} while ((t = strchr(t, ',')) != NULL);
	}
	argv = (const char **) alloca((argc + 1) * sizeof(char *));

	if (hosts)
		argc = 0;
	else
		argc = 1;

	/*
	 * If a mount of a hosts map is being requested it will come
	 * ro us via the options. Catch that below when processing the
	 * option and create type info struct then.
	 */
	if (hosts)
		info = parse_map_type_info("hosts:");
	else
		info = parse_map_type_info(what);
	if (!info) {
		error(ap->logopt, MODPREFIX "failed to parse map info");
		master_free_mapent(entry);
		return 1;
	}
	if (info->map)
		argv[0] = info->map;

	if (options) {
		p = options;
		do {
			if (*p == ',') {
				*p = '\0';
				p++;
			}
			argv[argc++] = p;
		} while ((p = strchr(p, ',')) != NULL);
	}
	argv[argc] = NULL;

	/*
	 * For amd type "auto" the map is often re-used so check
	 * if the the parent map can be used and use it if it
	 * matches.
	 *
	 * Also if the parent map format is amd and the format
	 * isn't specified in the map entry set it from the parent
	 * map source.
	 */
	source = NULL;
	if (ap->entry->maps && ap->entry->maps->flags & MAP_FLAG_FORMAT_AMD) {
		struct map_source *s = ap->entry->maps;

		/*
		 * For amd maps, if the format and source type aren't
		 * specified try and set them from the parent.
		 */
		if (!info->format) {
			info->format = strdup("amd");
			if (!info->format)
				warn(ap->logopt, MODPREFIX
				     "failed to set amd map format");
			if (!info->type && s->type) {
				info->type = strdup(s->type);
				if (!info->type)
					warn(ap->logopt, MODPREFIX
					     "failed to set amd map type");
			}
		}

		source = master_get_map_source(ap->entry,
					       info->type, info->format,
					       argc, argv);
		if (source)
			entry->maps = source;
	}

	if (!source)
		source = master_add_map_source(entry,
					       info->type, info->format,
					       monotonic_time(NULL),
					       argc, argv);
	if (!source) {
		error(ap->logopt,
		      MODPREFIX "failed to add map source to entry");
		master_free_mapent(entry);
		free_map_type_info(info);
		return 1;
	}
	free_map_type_info(info);

	set_exp_timeout(nap, NULL, timeout);
	nap->exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;

	if (source->flags & MAP_FLAG_FORMAT_AMD) {
		struct mnt_list *mnt;

		mnt = mnts_find_amdmount(entry->path);
		if (mnt) {
			if (mnt->amd_pref) {
				nap->pref = mnt->amd_pref;
				mnt->amd_pref = NULL;
			}

			if (mnt->amd_cache_opts & AMD_CACHE_OPTION_ALL)
				nap->flags |= MOUNT_FLAG_AMD_CACHE_ALL;

			mnts_put_mount(mnt);
		}
	}

	if (handle_mounts_startup_cond_init(&suc)) {
		crit(ap->logopt, MODPREFIX
		     "failed to init startup cond for mount %s", entry->path);
		master_free_map_source(source, 1);
		master_free_mapent(entry);
		return 1;
	}

	mnt = mnts_add_submount(nap);
	if (!mnt) {
		crit(ap->logopt,
		     MODPREFIX "failed to allocate mount %s", mountpoint);
		handle_mounts_startup_cond_destroy(&suc);
		master_free_map_source(source, 1);
		master_free_mapent(entry);
		return 1;
	}


	suc.ap = nap;
	suc.done = 0;
	suc.status = 0;

	if (pthread_create(&thid, &th_attr, handle_mounts, &suc)) {
		crit(ap->logopt,
		     MODPREFIX
		     "failed to create mount handler thread for %s",
		     mountpoint);
		handle_mounts_startup_cond_destroy(&suc);
		mnts_remove_submount(nap->path);
		master_free_map_source(source, 1);
		master_free_mapent(entry);
		return 1;
	}

	while (!suc.done) {
		status = pthread_cond_wait(&suc.cond, &suc.mutex);
		if (status) {
			handle_mounts_startup_cond_destroy(&suc);
			mnts_remove_submount(nap->path);
			master_free_map_source(source, 1);
			master_free_mapent(entry);
			fatal(status);
		}
	}

	if (suc.status) {
		crit(ap->logopt,
		     MODPREFIX "failed to create submount for %s", mountpoint);
		handle_mounts_startup_cond_destroy(&suc);
		mnts_remove_submount(nap->path);
		master_free_map_source(source, 1);
		master_free_mapent(entry);
		return 1;
	}
	nap->thid = thid;

	handle_mounts_startup_cond_destroy(&suc);

	return 0;
}

int mount_done(void *context)
{
	return 0;
}
