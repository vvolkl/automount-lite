/*
 * automount.h
 *
 * Header file for automounter modules
 *
 */

#ifndef AUTOMOUNT_H
#define AUTOMOUNT_H

#include <stdio.h>
#include <paths.h>
#include <limits.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <mntent.h>
#include "config.h"
#include "list.h"
#include "hash.h"

#include <linux/auto_fs4.h>

#include "defaults.h"
#include "state.h"
#include "master.h"
#include "macros.h"
#include "log.h"
#include "mounts.h"
#include "rpc_subs.h"
#include "parse_subs.h"
#include "dev-ioctl-lib.h"
#include "parse_amd.h"

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif

#define ENABLE_CORES	1

#ifndef __GLIBC__
# define strerror_r(N,B,S) autofs_strerror_r(N,B,S)
char *autofs_strerror_r(int errnum, char *buf, size_t buflen);  /* GNU */
#endif

/* We MUST have the paths to mount(8) and umount(8) */
#ifndef HAVE_MOUNT
#error Failed to locate mount(8)!
#endif

#ifndef HAVE_UMOUNT
#error Failed to locate umount(8)!
#endif

#ifndef HAVE_LINUX_PROCFS
#error Failed to verify existence of procfs filesystem!
#endif

/* The -s (sloppy) option to mount is good, if we have it... */

#ifdef HAVE_SLOPPY_MOUNT
#define SLOPPYOPT "-s",		/* For use in spawnl() lists */
#define SLOPPY    "-s "		/* For use in strings */
#else
#define SLOPPYOPT
#define SLOPPY
#endif

#define DAEMON_FLAGS_FOREGROUND			0x0001
#define DAEMON_FLAGS_SYSTEMD_SERVICE		0x0002
#define DAEMON_FLAGS_HAVE_GLOBAL_OPTIONS	0x0004
#define DAEMON_FLAGS_GHOST			0x0008
#define DAEMON_FLAGS_CHECK_DAEMON		0x0010
#define DAEMON_FLAGS_DUMP_MAPS			0x0020

#define AUTOFS_SUPER_MAGIC 0x00000187L
#define SMB_SUPER_MAGIC    0x0000517BL
#define CIFS_MAGIC_NUMBER  0xFF534D42L
#define NCP_SUPER_MAGIC    0x0000564CL
#define NFS_SUPER_MAGIC    0x00006969L

#define ATTEMPT_ID_SIZE 24

/* This sould be enough for at least 20 host aliases */
#define HOST_ENT_BUF_SIZE	2048

#define CHECK_RATIO	4			/* exp_runfreq = exp_timeout/CHECK_RATIO */
#define AUTOFS_LOCK	"/var/lock/autofs"	/* To serialize access to mount */
#define MOUNTED_LOCK	_PATH_MOUNTED "~"	/* mounts' lock file */
#define MTAB_NOTUPDATED 0x1000			/* mtab succeded but not updated */
#define NOT_MOUNTED     0x0100			/* path notmounted */
#define MNT_FORCE_FAIL	-1
#define _PROC_MOUNTS		"/proc/mounts"
#define _PROC_SELF_MOUNTS	"/proc/self/mounts"

/* Constants for lookup modules */

#define LKP_FAIL	0x0001

#define LKP_INDIRECT	0x0002
#define LKP_DIRECT	0x0004
#define LKP_MULTI	0x0008
#define LKP_NOMATCH	0x0010
#define LKP_MATCH	0x0020
#define LKP_NEXT	0x0040
#define LKP_MOUNT	0x0080
#define LKP_WILD	0x0100
#define LKP_LOOKUP	0x0200
#define LKP_GHOST	0x0400
#define LKP_REREAD	0x0800
#define LKP_NORMAL	0x1000
#define LKP_DISTINCT	0x2000
#define LKP_ERR_MOUNT	0x4000
#define LKP_NOTSUP	0x8000

#define MAX_ERR_BUF	128

#ifdef DEBUG
#define DB(x)           do { x; } while(0)
#else
#define DB(x)           do { } while(0)
#endif

#define min(a, b)	(a <= b ? a : b)

/* Forward declaraion */
struct autofs_point; 

/* mapent cache definition */

#define CHE_FAIL	0x0000
#define CHE_OK		0x0001
#define CHE_UPDATED	0x0002
#define CHE_RMPATH	0x0004
#define CHE_MISSING	0x0008
#define CHE_COMPLETED	0x0010
#define CHE_DUPLICATE	0x0020
#define CHE_UNAVAIL	0x0040

#define NULL_MAP_HASHSIZE	64
#define NEGATIVE_TIMEOUT	10
#define POSITIVE_TIMEOUT	120
#define UMOUNT_RETRIES		16
#define EXPIRE_RETRIES		1

struct mapent_cache {
	pthread_rwlock_t rwlock;
	unsigned int size;
	pthread_mutex_t ino_index_mutex;
	struct list_head *ino_index;
	struct autofs_point *ap;
	struct map_source *map;
	struct mapent **hash;
};

struct stack {
	char *mapent;
	time_t age;
	struct stack *next;
};

struct mapent {
	struct mapent *next;
	struct list_head ino_index;
	struct mapent_cache *mc;
	struct map_source *source;
	/* Need to know owner if we're a multi-mount */
	struct tree_node *mm_root;
	/* Parent nesting point within multi-mount */
	struct tree_node *mm_parent;
	struct tree_node node;
	struct list_head work;
	char *key;
	size_t len;
	char *mapent;
	struct stack *stack;
	time_t age;
	/* Time of last mount fail */
	time_t status;
	/* For direct mounts per entry context is kept here */
	int flags;
	/* File descriptor for ioctls */
	int ioctlfd;
	dev_t dev;
	ino_t ino;
};

#define IS_MM(me)	(me->mm_root)
#define IS_MM_ROOT(me)	(me->mm_root == &me->node)
#define MM_ROOT(me)	(MAPENT(me->mm_root))
#define MM_PARENT(me)	(MAPENT(me->mm_parent))

void cache_lock_cleanup(void *arg);
void cache_readlock(struct mapent_cache *mc);
void cache_writelock(struct mapent_cache *mc);
int cache_try_writelock(struct mapent_cache *mc);
void cache_unlock(struct mapent_cache *mc);
int cache_push_mapent(struct mapent *me, char *mapent);
int cache_pop_mapent(struct mapent *me);
struct mapent_cache *cache_init(struct autofs_point *ap, struct map_source *map);
struct mapent_cache *cache_init_null_cache(struct master *master);
int cache_set_ino_index(struct mapent_cache *mc, struct mapent *me);
struct mapent *cache_lookup_ino(struct mapent_cache *mc, dev_t dev, ino_t ino);
struct mapent *cache_lookup_first(struct mapent_cache *mc);
struct mapent *cache_lookup_next(struct mapent_cache *mc, struct mapent *me);
struct mapent *cache_lookup_key_next(struct mapent *me);
struct mapent *cache_lookup(struct mapent_cache *mc, const char *key);
struct mapent *cache_lookup_distinct(struct mapent_cache *mc, const char *key);
struct mapent *cache_partial_match(struct mapent_cache *mc, const char *prefix);
struct mapent *cache_partial_match_wild(struct mapent_cache *mc, const char *prefix);
int cache_add(struct mapent_cache *mc, struct map_source *ms, const char *key, const char *mapent, time_t age);
int cache_update_offset(struct mapent_cache *mc, const char *mkey, const char *key, const char *mapent, time_t age);
int cache_lookup_negative(struct mapent *me, const char *key);
void cache_update_negative(struct mapent_cache *mc, struct map_source *ms, const char *key, time_t timeout);
struct mapent *cache_get_offset_parent(struct mapent_cache *mc, const char *key);
int cache_update(struct mapent_cache *mc, struct map_source *ms, const char *key, const char *mapent, time_t age);
int cache_delete(struct mapent_cache *mc, const char *key);
void cache_release(struct map_source *map);
void cache_clean_null_cache(struct mapent_cache *mc);
void cache_release_null_cache(struct master *master);
struct mapent *cache_enumerate(struct mapent_cache *mc, struct mapent *me);

/* Utility functions */

char **add_argv(int argc, char **argv, char *str);
char **append_argv(int argc1, char **argv1, int argc2, char **argv2);
const char **copy_argv(int argc, const char **argv);
int compare_argv(int argc1, const char **argv1, int argc2, const char **argv2);
int free_argv(int argc, const char **argv);

struct pending_args;
void set_thread_mount_request_log_id(struct pending_args *mt);

void dump_core(void);
int aquire_lock(void);
void release_lock(void);
int spawnl(unsigned logopt, const char *prog, ...);
int spawnv(unsigned logopt, const char *prog, const char *const *argv);
int spawn_mount(unsigned logopt, ...);
int spawn_bind_mount(unsigned logopt, ...);
int spawn_umount(unsigned logopt, ...);
void open_mutex_lock(void);
void open_mutex_unlock(void);
int open_fd(const char *, int);
int open_fd_mode(const char *, int, int);
int open_pipe(int[2]);
int open_sock(int, int, int);
FILE *open_fopen_r(const char *);
FILE *open_setmntent_r(const char *);
void reset_signals(void);
int do_mount(struct autofs_point *ap, const char *root, const char *name,
	     int name_len, const char *what, const char *fstype,
	     const char *options);
extern unsigned int mp_mode;
int mkdir_path(const char *path, mode_t mode);
int rmdir_path(struct autofs_point *ap, const char *path, dev_t dev);

/* Prototype for module functions */

/* lookup module */

#define AUTOFS_LOOKUP_VERSION 5

#define KEY_MAX_LEN    NAME_MAX
#define MAPENT_MAX_LEN 16384
#define PARSE_MAX_BUF	KEY_MAX_LEN + MAPENT_MAX_LEN + 2

int lookup_nss_read_master(struct master *master, time_t age);
int lookup_nss_read_map(struct autofs_point *ap, struct map_source *source, time_t age);
int lookup_enumerate(struct autofs_point *ap,
	int (*fn)(struct autofs_point *,struct mapent *, int), time_t now);
int lookup_ghost(struct autofs_point *ap);
int lookup_nss_mount(struct autofs_point *ap, struct map_source *source, const char *name, int name_len);
void lookup_close_lookup(struct autofs_point *ap);
void lookup_prune_one_cache(struct autofs_point *ap, struct mapent_cache *mc, time_t age);
int lookup_prune_cache(struct autofs_point *ap, time_t age);
struct mapent *lookup_source_valid_mapent(struct autofs_point *ap, const char *key, unsigned int type);
struct mapent *lookup_source_mapent(struct autofs_point *ap, const char *key, unsigned int type);
int lookup_source_close_ioctlfd(struct autofs_point *ap, const char *key);

#ifdef MODULE_LOOKUP
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context);
int lookup_reinit(const char *mapfmt, int argc, const char *const *argv, void **context);
int lookup_read_master(struct master *master, time_t age, void *context);
int lookup_read_map(struct autofs_point *ap, struct map_source *map, time_t age, void *context);
int lookup_mount(struct autofs_point *, struct map_source *map, const char *name, int name_len, void *context);
int lookup_done(void *);
#endif
typedef int (*lookup_init_t) (const char *, int, const char *const *, void **);
typedef int (*lookup_reinit_t) (const char *, int, const char *const *, void **);
typedef int (*lookup_read_master_t) (struct master *master, time_t, void *);
typedef int (*lookup_read_map_t) (struct autofs_point *, struct map_source *, time_t, void *);
typedef int (*lookup_mount_t) (struct autofs_point *, struct map_source *, const char *, int, void *);
typedef int (*lookup_done_t) (void *);

struct lookup_mod {
	lookup_init_t lookup_init;
	lookup_reinit_t lookup_reinit;
	lookup_read_master_t lookup_read_master;
	lookup_read_map_t lookup_read_map;
	lookup_mount_t lookup_mount;
	lookup_done_t lookup_done;
	char *type;
	void *dlhandle;
	void *context;
};

int open_lookup(const char *name, const char *err_prefix, const char *mapfmt,
		int argc, const char *const *argv, struct lookup_mod **lookup);
int reinit_lookup(struct lookup_mod *mod, const char *name,
		  const char *err_prefix, const char *mapfmt,
		  int argc, const char *const *argv);
int close_lookup(struct lookup_mod *);

/* parse module */

#define AUTOFS_PARSE_VERSION 5

#ifdef MODULE_PARSE
int parse_init(int argc, const char *const *argv, void **context);
int parse_reinit(int argc, const char *const *argv, void **context);
int parse_mount(struct autofs_point *ap, struct map_source *map,
		const char *name, int name_len, const char *mapent,
		void *context);
int parse_done(void *);
#endif
typedef int (*parse_init_t) (int, const char *const *, void **);
typedef int (*parse_reinit_t) (int, const char *const *, void **);
typedef int (*parse_mount_t) (struct autofs_point *, struct map_source *,
				const char *, int, const char *, void *);
typedef int (*parse_done_t) (void *);

struct parse_mod {
	parse_init_t parse_init;
	parse_reinit_t parse_reinit;
	parse_mount_t parse_mount;
	parse_done_t parse_done;
	void *dlhandle;
	void *context;
};

struct parse_mod *open_parse(const char *name, const char *err_prefix,
			     int argc, const char *const *argv);
int reinit_parse(struct parse_mod *, const char *name,
		 const char *err_prefix, int argc, const char *const *argv);
int close_parse(struct parse_mod *);

/* mount module */

#define AUTOFS_MOUNT_VERSION 4

#ifdef MODULE_MOUNT
int mount_init(void **context);
int mount_reinit(void **context);
int mount_mount(struct autofs_point *ap, const char *root, const char *name, int name_len,
		const char *what, const char *fstype, const char *options, void *context);
int mount_done(void *context);
#endif
typedef int (*mount_init_t) (void **);
typedef int (*mount_reinit_t) (void **);
typedef int (*mount_mount_t) (struct autofs_point *, const char *, const char *, int,
				const char *, const char *, const char *, void *);
typedef int (*mount_done_t) (void *);

struct mount_mod {
	mount_init_t mount_init;
	mount_reinit_t mount_reinit;
	mount_mount_t mount_mount;
	mount_done_t mount_done;
	void *dlhandle;
	void *context;
};

struct mount_mod *open_mount(const char *name, const char *err_prefix);
int reinit_mount(struct mount_mod *mod, const char *name, const char *err_prefix);
int close_mount(struct mount_mod *);

/* buffer management */

size_t _strlen(const char *str, size_t max);
int cat_path(char *buf, size_t len, const char *dir, const char *base);
int ncat_path(char *buf, size_t len,
              const char *dir, const char *base, size_t blen);
int _strncmp(const char *s1, const char *s2, size_t n);

/* Core automount definitions */

#ifndef MNT_DETACH
#define MNT_DETACH	0x00000002	/* Just detach from the tree */
#endif

struct startup_cond {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	struct autofs_point *ap;
	unsigned int done;
	unsigned int status;
};

int handle_mounts_startup_cond_init(struct startup_cond *suc);
void handle_mounts_startup_cond_destroy(void *arg);

struct master_readmap_cond {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	pthread_t thid;		 /* map reader thread id */
	struct master *master;
	time_t age;		 /* Last time read */
	enum states state;	 /* Next state */
	unsigned int signaled;   /* Condition has been signaled */
	unsigned int busy;	 /* Map read in progress. */
};

struct pending_args {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	unsigned int signaled;		/* Condition has been signaled */
	struct autofs_point *ap;	/* autofs mount we are working on */
	int status;			/* Return status */
	int type;			/* Type of packet */
	int ioctlfd;			/* Mount ioctl fd */
	struct mapent_cache *mc;	/* Cache Containing entry */
	char name[PATH_MAX];		/* Name field of the request */
	dev_t dev;			/* device number of mount */
	unsigned int len;		/* Name field len */
	uid_t uid;			/* uid of requester */
	gid_t gid;			/* gid of requester */
	pid_t pid;			/* pid of requestor */
	unsigned long wait_queue_token;	/* Associated kernel wait token */
};

#ifdef INCLUDE_PENDING_FUNCTIONS
static void pending_cond_init(void *arg)
{
	struct pending_args *mt = (struct pending_args *) arg;
	pthread_condattr_t condattrs;
	int status;

	status = pthread_condattr_init(&condattrs);
	if (status)
		fatal(status);

	status = pthread_condattr_setclock(&condattrs, CLOCK_MONOTONIC);
	if (status)
		fatal(status);

	status = pthread_cond_init(&mt->cond, &condattrs);
	if (status)
		fatal(status);

	pthread_condattr_destroy(&condattrs);
}

static void pending_cond_destroy(void *arg)
{
	struct pending_args *mt = (struct pending_args *) arg;
	int status;
	status = pthread_cond_destroy(&mt->cond);
	if (status)
		fatal(status);
}

static void pending_mutex_destroy(void *arg)
{
	struct pending_args *mt = (struct pending_args *) arg;
	int status = pthread_mutex_destroy(&mt->mutex);
	if (status)
		fatal(status);
}

static void free_pending_args(void *arg)
{
	struct pending_args *mt = (struct pending_args *) arg;
	free(mt);
}

static void pending_mutex_lock(void *arg)
{
        struct pending_args *mt = (struct pending_args *) arg;
        int status = pthread_mutex_lock(&mt->mutex);
        if (status)
                fatal(status);
}

static void pending_mutex_unlock(void *arg)
{
        struct pending_args *mt = (struct pending_args *) arg;
        int status = pthread_mutex_unlock(&mt->mutex);
        if (status)
                fatal(status);
}
#endif

struct thread_stdenv_vars {
	uid_t uid;
	gid_t gid;
	char *user;
	char *group;
	char *home;
};

extern pthread_key_t key_thread_stdenv_vars;

extern pthread_key_t key_thread_attempt_id;

struct kernel_mod_version {
	unsigned int major;
	unsigned int minor;
};

/* Enable/disable ghosted directories */
#define MOUNT_FLAG_GHOST		0x0001

/* Directory created for this mount? */
#define MOUNT_FLAG_DIR_CREATED		0x0002

/* Use random policy when selecting a host from which to mount */
#define MOUNT_FLAG_RANDOM_SELECT	0x0004

/* Mount being re-mounted */
#define MOUNT_FLAG_REMOUNT		0x0008

/* Use server weight only for selection */
#define MOUNT_FLAG_USE_WEIGHT_ONLY	0x0010

/* Don't use bind mounts even when system supports them */
#define MOUNT_FLAG_NOBIND		0x0020

/* Use symlinks instead of bind mounting local mounts */
#define MOUNT_FLAG_SYMLINK		0x0040

/* Read amd map even if it's not to be ghosted (browsable) */
#define MOUNT_FLAG_AMD_CACHE_ALL	0x0080

/* Set mount propagation for bind mounts */
#define MOUNT_FLAG_SHARED		0x0100
#define MOUNT_FLAG_SLAVE		0x0200
#define MOUNT_FLAG_PRIVATE		0x0400

/* Use strict expire semantics if requested and kernel supports it */
#define MOUNT_FLAG_STRICTEXPIRE		0x0800

/* Indicator for applications to ignore the mount entry */
#define MOUNT_FLAG_IGNORE		0x1000

struct autofs_point {
	pthread_t thid;
	char *path;			/* Mount point name */
	size_t len;			/* Length of mount point name */
	mode_t mode;			/* Mount point mode */
	char *pref;			/* amd prefix */
	int pipefd;			/* File descriptor for pipe */
	int kpipefd;			/* Kernel end descriptor for pipe */
	int ioctlfd;			/* File descriptor for ioctls */
	dev_t dev;			/* "Device" number assigned by kernel */
	struct master_mapent *entry;	/* Master map entry for this mount */
	unsigned int type;		/* Type of map direct or indirect */
	time_t exp_timeout;		/* Indirect mount expire timeout */
	time_t exp_runfreq;		/* Frequency for polling for timeouts */
	time_t negative_timeout;	/* timeout in secs for failed mounts */
	time_t positive_timeout;	/* timeout in secs for using cache for map entries */
	unsigned int flags;		/* autofs mount flags */
	unsigned int logopt;		/* Per map logging */
	pthread_t exp_thread;		/* Thread that is expiring */
	pthread_t readmap_thread;	/* Thread that is reading maps */
	enum states state;		/* Current state */
	struct autofs_point *parent;	/* Owner of mounts list for submount */
	struct list_head mounts;	/* List of autofs mounts at current level */
	unsigned int submount;		/* Is this a submount */
	struct list_head submounts;	/* List of child submounts */
	struct list_head amdmounts;	/* List of non submount amd mounts */
	unsigned int shutdown;		/* Shutdown notification */
};

#define UNLINK_AND_CONT		0x01
#define UNLINK_AND_EXIT		0x02

/* Foreably unlink existing mounts at startup. */
extern int do_force_unlink;

/* Standard functions used by daemon or modules */

#define	MOUNT_OFFSET_OK		0
#define	MOUNT_OFFSET_FAIL	-1
#define MOUNT_OFFSET_IGNORE	-2

void *handle_mounts(void *arg);
int umount_multi(struct autofs_point *ap, const char *path, int incl);
int do_expire(struct autofs_point *ap, const char *name, int namelen);
void *expire_proc_indirect(void *);
void *expire_proc_direct(void *);
int expire_offsets_direct(struct autofs_point *ap, struct mapent *me, int now);
int mount_autofs_indirect(struct autofs_point *ap);
int do_mount_autofs_direct(struct autofs_point *ap, struct mapent *me, time_t timeout);
int mount_autofs_direct(struct autofs_point *ap);
int mount_autofs_offset(struct autofs_point *ap, struct mapent *me);
void submount_signal_parent(struct autofs_point *ap, unsigned int success);
void close_mount_fds(struct autofs_point *ap);
int umount_autofs_indirect(struct autofs_point *ap);
int do_umount_autofs_direct(struct autofs_point *ap, struct mapent *me);
int umount_autofs_direct(struct autofs_point *ap);
int umount_autofs_offset(struct autofs_point *ap, struct mapent *me);
int handle_packet_expire_indirect(struct autofs_point *ap, autofs_packet_expire_indirect_t *pkt);
int handle_packet_expire_direct(struct autofs_point *ap, autofs_packet_expire_direct_t *pkt);
int handle_packet_missing_indirect(struct autofs_point *ap, autofs_packet_missing_indirect_t *pkt);
int handle_packet_missing_direct(struct autofs_point *ap, autofs_packet_missing_direct_t *pkt);
void rm_unwanted(struct autofs_point *ap, const char *path, int incl);
int count_mounts(struct autofs_point *ap, const char *path, dev_t dev);

#define mounts_mutex_lock(ap) \
do { \
	int _m_lock = pthread_mutex_lock(&ap->mounts_mutex); \
	if (_m_lock) \
		fatal(_m_lock); \
} while (0)

#define mounts_mutex_unlock(ap) \
do { \
	int _m_unlock = pthread_mutex_unlock(&ap->mounts_mutex); \
	if (_m_unlock) \
		fatal(_m_unlock); \
} while(0)

static inline time_t monotonic_time(time_t *t)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	if (t)
		*t = (time_t) ts.tv_sec;
	return (time_t) ts.tv_sec;
}

/* Expire alarm handling routines */
int alarm_start_handler(void);
int alarm_add(struct autofs_point *ap, time_t seconds);
int conditional_alarm_add(struct autofs_point *ap, time_t seconds);
void alarm_delete(struct autofs_point *ap);

#endif

