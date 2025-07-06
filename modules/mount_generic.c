/* ----------------------------------------------------------------------- *
 *   
 *  mount_generic.c - module for Linux automountd to mount filesystems
 *                    for which no special magic is required
 *
 *   Copyright 1997-1999 Transmeta Corporation - All Rights Reserved
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
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_MOUNT
#include "automount.h"

#define MODPREFIX "mount(generic): "

#ifndef ENABLE_STATIC_BUILD
int mount_version = AUTOFS_MOUNT_VERSION;	/* Required by protocol */
#endif

int mount_generic_init(void **context)
{
	return 0;
}

int mount_generic_reinit(void **context)
{
	return 0;
}

int mount_generic_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options,
		void *context)
{
	char fullpath[PATH_MAX];
	char buf[MAX_ERR_BUF];
	int err;
	int len, status, existed = 1;
	void (*mountlog)(unsigned int, const char*, ...) = &log_debug;

	if (ap->flags & MOUNT_FLAG_REMOUNT)
		return 0;

	if (defaults_get_mount_verbose())
		mountlog = &log_info;

	len = mount_fullpath(fullpath, PATH_MAX, root, 0, name);
	if (!len) {
		error(ap->logopt,
		      MODPREFIX "mount point path too long");
		return 1;
	}

	debug(ap->logopt, MODPREFIX "calling mkdir_path %s", fullpath);

	status = mkdir_path(fullpath, mp_mode);
	if (status && errno != EEXIST) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt,
		      MODPREFIX "mkdir_path %s failed: %s", fullpath, estr);
		return 1;
	}

	if (!status)
		existed = 0;

	if (options && options[0]) {
		mountlog(ap->logopt,
			 MODPREFIX "calling mount -t %s -o %s %s %s",
			 fstype, options, what, fullpath);

		err = spawn_mount(ap->logopt, "-t", fstype,
				  "-o", options, what, fullpath, NULL);
	} else {
		mountlog(ap->logopt, MODPREFIX "calling mount -t %s %s %s",
			 fstype, what, fullpath);
		err = spawn_mount(ap->logopt, "-t", fstype, what, fullpath, NULL);
	}

	if (err) {
		info(ap->logopt, MODPREFIX "failed to mount %s (type %s) on %s",
		     what, fstype, fullpath);

		if (ap->type != LKP_INDIRECT)
			return 1;

		if ((!(ap->flags & MOUNT_FLAG_GHOST) && name_len) || !existed)
			rmdir_path(ap, fullpath, ap->dev);

		return 1;
	} else {
		mountlog(ap->logopt, MODPREFIX "mounted %s type %s on %s",
		     what, fstype, fullpath);
		return 0;
	}
}

int mount_generic_done(void *context)
{
	return 0;
}
