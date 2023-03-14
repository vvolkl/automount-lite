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
#define MNTS_AMD_MOUNT	0x0040
#define MNTS_MOUNTED	0x0080

#define REMOUNT_SUCCESS		0x0000
#define REMOUNT_FAIL		0x0001
#define REMOUNT_OPEN_FAIL	0x0002
#define REMOUNT_STAT_FAIL	0x0004
#define REMOUNT_READ_MAP	0x0008

extern const unsigned int t_indirect;
extern const unsigned int t_direct;
extern const unsigned int t_offset;

struct mnt_list;
struct exportinfo;
struct mapent;

struct tree_ops;

struct tree_node {
	struct tree_ops *ops;
	struct tree_node *left;
	struct tree_node *right;
};
#define INIT_TREE_NODE(ptr)	((ptr)->ops = NULL, (ptr)->left = NULL, (ptr)->right = NULL)

#define MNT_LIST(n)		(container_of(n, struct mnt_list, node))
#define MNT_LIST_NODE(ptr)	((struct tree_node *) &((struct mnt_list *) ptr)->node)

#define EXPORTINFO(n)		(container_of(n, struct exportinfo, node))
#define EXPORT_NODE(ptr)	((struct tree_node *) &((struct exportinfo *) ptr)->node)

#define MAPENT(n)		(container_of(n, struct mapent, node))
#define MAPENT_NODE(p)		((struct tree_node *) &((struct mapent *) p)->node)
#define MAPENT_ROOT(p)		((struct tree_node *) ((struct mapent *) p)->mm_root)
#define MAPENT_PARENT(p)	((struct tree_node *) ((struct mapent *) p)->mm_parent)
#define MAPENT_SET_ROOT(p, r)	{ (((struct mapent *) p)->mm_root = (struct tree_node *) r); }
#define MAPENT_SET_PARENT(p, n)	{ (((struct mapent *) p)->mm_parent = (struct tree_node *) n); }

typedef struct tree_node *(*tree_new_t) (void *ptr);
typedef int  (*tree_cmp_t) (struct tree_node *n, void *ptr);
typedef void (*tree_free_t) (struct tree_node *n);

struct tree_ops {
	tree_new_t new;
	tree_cmp_t cmp;
	tree_free_t free;
};

typedef int (*tree_work_fn_t) (struct tree_node *n, void *ptr);

struct mnt_list {
	char *mp;
	size_t len;
	unsigned int flags;

	/* Hash of all mounts */
	struct hlist_node hash;
	unsigned int ref;

	/* List of mounts of an autofs_point */
	struct list_head mount;
	/* Mounted mounts list for expire */
	struct list_head expire;

	/* List of sub-mounts of an autofs_point */
	struct autofs_point *ap;
	struct list_head submount;
	struct list_head submount_work;

	/* List of amd-mounts of an autofs_point */
	char *ext_mp;
	char *amd_pref;
	char *amd_type;
	char *amd_opts;
	unsigned int amd_cache_opts;
	struct list_head amdmount;

	/* Tree operations */
	struct tree_node node;

	/*
	 * List operations ie. get_mnt_list.
	 */
	struct mnt_list *next;
};

struct nfs_mount_vers {
	unsigned int major;
	unsigned int minor;
	unsigned int fix;
};
unsigned int linux_version_code(void);
int check_nfs_mount_version(struct nfs_mount_vers *, struct nfs_mount_vers *);
extern unsigned int nfs_mount_uses_string_options;

int mount_fullpath(char *fullpath, size_t max_len,
		   const char *root, size_t root_len, const char *name);

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

int open_ioctlfd(struct autofs_point *ap, const char *path, dev_t dev);

char *make_options_string(char *path, int pipefd,
			  const char *type, unsigned int flags);
char *make_mnt_name_string(char *path);
int ext_mount_add(const char *, const char *);
int ext_mount_remove(const char *);
int ext_mount_inuse(const char *);
struct mnt_list *mnts_lookup_mount(const char *mp);
void mnts_put_mount(struct mnt_list *mnt);
struct mnt_list *mnts_find_submount(const char *path);
struct autofs_point *mnt_find_submount_by_devid(struct list_head *submounts, dev_t devid);
struct mnt_list *mnts_add_submount(struct autofs_point *ap);
void mnts_remove_submount(const char *mp);
struct mnt_list *mnts_find_amdmount(const char *path);
struct mnt_list *mnts_add_amdmount(struct autofs_point *ap, struct amd_entry *entry);
void mnts_remove_amdmount(const char *mp);
void mnts_remove_amdmounts(struct autofs_point *ap);
struct mnt_list *mnts_add_mount(struct autofs_point *ap, const char *name, unsigned int flags);
void mnts_remove_mount(const char *mp, unsigned int flags);
struct mnt_list *get_mnt_list(const char *path, int include);
unsigned int mnts_has_mounted_mounts(struct autofs_point *ap);
int tree_traverse_inorder(struct tree_node *n, tree_work_fn_t work, void *ptr);
void tree_free(struct tree_node *root);
void mnts_get_expire_list(struct list_head *mnts, struct autofs_point *ap);
void mnts_put_expire_list(struct list_head *mnts);
void mnts_set_mounted_mount(struct autofs_point *ap, const char *name, unsigned int flags);
struct tree_node *tree_host_root(struct exportinfo *exp);
struct tree_node *tree_host_add_node(struct tree_node *root, struct exportinfo *exp);
struct tree_node *tree_mapent_root(struct mapent *me);
int tree_mapent_add_node(struct mapent_cache *mc, struct tree_node *root, struct mapent *me);
int tree_mapent_delete_offsets(struct mapent_cache *mc, const char *key);
void tree_mapent_cleanup_offsets(struct mapent *oe);
int tree_mapent_mount_offsets(struct mapent *oe, int nonstrict);
int tree_mapent_umount_offsets(struct mapent *oe);
int unlink_mount_tree(struct autofs_point *ap, const char *mp);
void free_mnt_list(struct mnt_list *list);
int is_mounted(const char *mp, unsigned int type);
void set_tsd_user_vars(unsigned int, uid_t, gid_t);
const char *mount_type_str(unsigned int);
void set_exp_timeout(struct autofs_point *ap, struct map_source *source, time_t timeout);
time_t get_exp_timeout(struct autofs_point *ap, struct map_source *source);
void notify_mount_result(struct autofs_point *, const char *, time_t, const char *);
int try_remount(struct autofs_point *, struct mapent *, unsigned int);
void set_indirect_mount_tree_catatonic(struct autofs_point *);
void set_direct_mount_tree_catatonic(struct autofs_point *, struct mapent *);
int umount_ent(struct autofs_point *, const char *);
int umount_amd_ext_mount(struct autofs_point *, const char *);
int clean_stale_multi_triggers(struct autofs_point *, struct mapent *, char *, const char *);

#endif
