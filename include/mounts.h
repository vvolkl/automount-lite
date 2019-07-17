/* ----------------------------------------------------------------------- *
 *
 *  mounts.h - header file for mount utilities module.
 *
 *   Copyright 2008 Red Hat, Inc. All rights reserved.
 *   Copyright 2004-2006 Ian Kent <raven@themaw.net> - All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef MOUNTS_H
#define MOUNTS_H

#include <linux/version.h>
#include <sys/utsname.h>

#ifndef AUTOFS_TYPE_ANY
#define AUTOFS_TYPE_ANY		0x0000
#endif
#ifndef AUTOFS_TYPE_INDIRECT
#define AUTOFS_TYPE_INDIRECT	0x0001
#endif
#ifndef AUTOFS_TYPE_DIRECT
#define AUTOFS_TYPE_DIRECT	0x0002
#endif
#ifndef AUTOFS_TYPE_OFFSET
#define AUTOFS_TYPE_OFFSET	0x0004
#endif

#define MNTS_ALL	0x0001
#define MNTS_REAL	0x0002
#define MNTS_AUTOFS	0x0004
#define MNTS_INDIRECT	0x0008
#define MNTS_DIRECT	0x0010
#define MNTS_OFFSET	0x0020

#define REMOUNT_SUCCESS		0x0000
#define REMOUNT_FAIL		0x0001
#define REMOUNT_OPEN_FAIL	0x0002
#define REMOUNT_STAT_FAIL	0x0004
#define REMOUNT_READ_MAP	0x0008

extern const unsigned int t_indirect;
extern const unsigned int t_direct;
extern const unsigned int t_offset;

struct mapent;

struct mnt_list {
	char *mp;
	unsigned int flags;
	/*
	 * List operations ie. get_mnt_list.
	 */
	struct mnt_list *next;
	/*
	 * Tree operations ie. tree_make_tree,
	 * tree_get_mnt_list etc.
	 */
	struct mnt_list *left;
	struct mnt_list *right;
	struct list_head self;
	struct list_head list;
	struct list_head entries;
	struct list_head sublist;
};


struct nfs_mount_vers {
	unsigned int major;
	unsigned int minor;
	unsigned int fix;
};
unsigned int linux_version_code(void);
int check_nfs_mount_version(struct nfs_mount_vers *, struct nfs_mount_vers *);
extern unsigned int nfs_mount_uses_string_options;

struct amd_entry;

struct substvar *addstdenv(struct substvar *sv, const char *prefix);
struct substvar *removestdenv(struct substvar *sv, const char *prefix);
void add_std_amd_vars(struct substvar *sv);
void remove_std_amd_vars(void);
struct amd_entry *new_amd_entry(const struct substvar *sv);
void clear_amd_entry(struct amd_entry *entry);
void free_amd_entry(struct amd_entry *entry);
void free_amd_entry_list(struct list_head *entries);

unsigned int query_kproto_ver(void);
unsigned int get_kver_major(void);
unsigned int get_kver_minor(void);
char *make_options_string(char *path, int kernel_pipefd, const char *extra);
char *make_mnt_name_string(char *path);
int ext_mount_add(struct list_head *, const char *, unsigned int);
int ext_mount_remove(struct list_head *, const char *);
int ext_mount_inuse(const char *);
struct mnt_list *get_mnt_list(const char *path, int include);
int unlink_mount_tree(struct autofs_point *ap, const char *mp);
void free_mnt_list(struct mnt_list *list);
int is_mounted(const char *mp, unsigned int type);
void tree_free_mnt_tree(struct mnt_list *tree);
struct mnt_list *tree_make_mnt_tree(const char *path);
int tree_get_mnt_list(struct mnt_list *mnts, struct list_head *list, const char *path, int include);
int tree_get_mnt_sublist(struct mnt_list *mnts, struct list_head *list, const char *path, int include);
int tree_find_mnt_ents(struct mnt_list *mnts, struct list_head *list, const char *path);
void set_tsd_user_vars(unsigned int, uid_t, gid_t);
const char *mount_type_str(unsigned int);
void set_exp_timeout(struct autofs_point *ap, struct map_source *source, time_t timeout);
time_t get_exp_timeout(struct autofs_point *ap, struct map_source *source);
void notify_mount_result(struct autofs_point *, const char *, time_t, const char *);
int try_remount(struct autofs_point *, struct mapent *, unsigned int);
void set_indirect_mount_tree_catatonic(struct autofs_point *);
void set_direct_mount_tree_catatonic(struct autofs_point *, struct mapent *);
int umount_ent(struct autofs_point *, const char *);
int umount_amd_ext_mount(struct autofs_point *, struct amd_entry *);
int mount_multi_triggers(struct autofs_point *, struct mapent *, const char *, unsigned int, const char *);
int umount_multi_triggers(struct autofs_point *, struct mapent *, char *, const char *);
int clean_stale_multi_triggers(struct autofs_point *, struct mapent *, char *, const char *);

#endif
