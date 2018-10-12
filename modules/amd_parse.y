%{
/* ----------------------------------------------------------------------- *
 *
 *  Copyright 2013 Ian Kent <raven@themaw.net>
 *  Copyright 2013 Red Hat, Inc.
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *  USA; either version 2 of the License, or (at your option) any later
 *  version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <syslog.h>

#include "automount.h"
#include "parse_amd.h"
#include "log.h"

#define MAX_OPTS_LEN	1024
#define MAX_ERR_LEN	3096

static pthread_mutex_t parse_mutex = PTHREAD_MUTEX_INITIALIZER;

extern FILE *amd_in;
extern char *amd_text;
extern int amd_lex(void);
extern void amd_set_scan_buffer(const char *);

static char *amd_strdup(char *);
static void amd_set_value(char **, char *);
static void local_init_vars(void);
static void local_free_vars(void);

static int amd_error(const char *s);
static int amd_notify(const char *s);
static int amd_info(const char *s);
static int amd_msg(const char *s);

static int add_location(void);
static int make_selector(char *name,
			 char *value1, char *value2,
			 unsigned int compare);
static void add_selector(struct selector *selector);

static int match_map_option_fs_type(char *map_option, char *type);
static int match_map_option_map_type(char *map_option, char *type);
static int match_map_option_cache_option(char *type);
static int match_mnt_option_options(char *mnt_option, char *options);

static struct amd_entry entry;
static struct list_head *entries;
static struct autofs_point *pap;
struct substvar *psv;
static char opts[MAX_OPTS_LEN];
static void prepend_opt(char *, char *);
static char msg_buf[MAX_ERR_LEN];

#define YYDEBUG 0

#ifndef YYENABLE_NLS
#define YYENABLE_NLS 0
#endif
#ifndef YYLTYPE_IS_TRIVIAL
#define YYLTYPE_IS_TRIVIAL 0
#endif

#if YYDEBUG
static int amd_fprintf(FILE *, char *, ...);
#undef YYFPRINTF
#define YYFPRINTF amd_fprintf
#endif

%}

%union {
	char strtype[2048];
	int inttype;
	long longtype;
}

%token COMMENT
%token SEPERATOR
%token SPACE
%token HYPHEN
%token IS_EQUAL
%token CUT
%token NOT_EQUAL
%token COMMA
%token QUOTE
%token OPTION_ASSIGN
%token LBRACKET
%token RBRACKET
%token NOT
%token NILL

%token <strtype> MAP_OPTION
%token <strtype> MAP_TYPE
%token <strtype> CACHE_OPTION
%token <strtype> FS_TYPE
%token <strtype> FS_OPTION
%token <strtype> FS_OPT_VALUE
%token <strtype> MNT_OPTION
%token <strtype> SELECTOR
%token <strtype> SELECTOR_VALUE
%token <strtype> SEL_ARG_VALUE
%token <strtype> OPTION
%token <strtype> MACRO
%token <strtype> OTHER

%type <strtype> options

%start file

%%

file: {
#if YYDEBUG != 0
		amd_debug = YYDEBUG;
#endif
		memset(opts, 0, sizeof(opts));
	} line
	;

line:
	| location_selection_list
	;

location_selection_list: location
	{
		if (!add_location()) {
			amd_msg("failed to allocate new location");
			YYABORT;
		}
	}
	| location_selection_list SPACE location
	{
		if (!add_location()) {
			amd_msg("failed to allocate new location");
			YYABORT;
		}
	}
	| location_selection_list SPACE CUT SPACE location
	{
		entry.flags |= AMD_ENTRY_CUT;
		if (!add_location()) {
			amd_msg("failed to allocate new location");
			YYABORT;
		}
	}
	;

location: location_entry
	{
	}
	| HYPHEN location_entry
	{
		entry.flags |= AMD_DEFAULTS_MERGE;
	}
	| HYPHEN
	{
		entry.flags |= AMD_DEFAULTS_RESET;
	}
	;

location_entry: selector_or_option
	{
	}
	| location_entry SEPERATOR selector_or_option
	{
	}
	| location_entry SEPERATOR
	{
	}
	;

selector_or_option: selection
	{
	}
	| option_assignment
	{
	}
	| OTHER
	{
		amd_notify($1);
		YYABORT;
	}
	;

selection: SELECTOR IS_EQUAL SELECTOR_VALUE
	{
		if (!make_selector($1, $3, NULL, SEL_COMP_EQUAL)) {
			amd_notify($1);
			YYABORT;
		}
	}
	| SELECTOR IS_EQUAL
	{
		if (!make_selector($1, "", NULL, SEL_COMP_EQUAL)) {
			amd_notify($1);
			YYABORT;
		}
	}
	| SELECTOR NOT_EQUAL SELECTOR_VALUE
	{
		if (!make_selector($1, $3, NULL, SEL_COMP_NOTEQUAL)) {
			amd_notify($1);
			YYABORT;
		}
	}
	| SELECTOR NOT_EQUAL
	{
		if (!make_selector($1, "", NULL, SEL_COMP_EQUAL)) {
			amd_notify($1);
			YYABORT;
		}
	}
	| SELECTOR LBRACKET SEL_ARG_VALUE RBRACKET
	{
		if (!make_selector($1, $3, NULL, SEL_COMP_NONE)) {
			amd_notify($1);
			YYABORT;
		}
	}
	| SELECTOR LBRACKET SEL_ARG_VALUE COMMA SEL_ARG_VALUE RBRACKET
	{
		if (!make_selector($1, $3, $5, SEL_COMP_NONE)) {
			amd_notify($1);
			YYABORT;
		}
	}
	| NOT SELECTOR LBRACKET SEL_ARG_VALUE RBRACKET
	{
		if (!make_selector($2, $4, NULL, SEL_COMP_NOT)) {
			amd_notify($2);
			YYABORT;
		}
	}
	| NOT SELECTOR LBRACKET SEL_ARG_VALUE COMMA SEL_ARG_VALUE RBRACKET
	{
		if (!make_selector($2, $4, $6, SEL_COMP_NOT)) {
			amd_notify($2);
			YYABORT;
		}
	}
	;

option_assignment: MAP_OPTION OPTION_ASSIGN FS_TYPE
	{
		if (!match_map_option_fs_type($1, $3))
			YYABORT;
	}
	| MAP_OPTION OPTION_ASSIGN MAP_TYPE
	{
		if (!match_map_option_map_type($1, $3))
			YYABORT;
	}
	| MAP_OPTION OPTION_ASSIGN FS_OPT_VALUE
	{
		/* Quoted value for type, maptype or cache assign */
		if (!strcmp($1, "type")) {
			if (!match_map_option_fs_type($1, $3))
				YYABORT;
		} else if (!strcmp($1, "maptype")) {
			if (!match_map_option_map_type($1, $3))
				YYABORT;
		} else if (!strcmp($1, "cache")) {
			if (!match_map_option_cache_option($3))
				YYABORT;
		} else {
			char *fs_opt_val;

			fs_opt_val = amd_strdup($3);
			if (!fs_opt_val) {
				amd_notify($3);
				YYABORT;
			}

			if (!strcmp($1, "fs"))
				amd_set_value(&entry.fs, fs_opt_val);
			else if (!strcmp($1, "sublink")) {
				amd_set_value(&entry.sublink, fs_opt_val);
			} else if (!strcmp($1, "pref")) {
				if (strcmp(fs_opt_val, "null"))
					amd_set_value(&entry.pref, fs_opt_val);
				else {
					char *empty;

					empty = amd_strdup("");
					if (!empty) {
						amd_notify($3);
						free(fs_opt_val);
						YYABORT;
					}
					amd_set_value(&entry.pref, empty);
					free(fs_opt_val);
				}
			} else {
				amd_notify($1);
				free(fs_opt_val);
				YYABORT;
			}
		}
	}
	| MAP_OPTION OPTION_ASSIGN
	{
		if (!strcmp($1, "fs")) {
			char *empty;

			empty = amd_strdup("");
			if (!empty) {
				amd_notify($1);
				YYABORT;
			}
			amd_set_value(&entry.fs, empty);
		} else {
			amd_notify($1);
			YYABORT;
		}
	}
	| FS_OPTION OPTION_ASSIGN FS_OPT_VALUE
	{
		char *fs_opt_val;

		fs_opt_val = amd_strdup($3);
		if (!fs_opt_val) {
			amd_notify($1);
			YYABORT;
		}

		if (!strcmp($1, "rhost"))
			amd_set_value(&entry.rhost, fs_opt_val);
		else if (!strcmp($1, "rfs"))
			amd_set_value(&entry.rfs, fs_opt_val);
		else if (!strcmp($1, "dev"))
			amd_set_value(&entry.dev, fs_opt_val);
		else if (!strcmp($1, "mount"))
			amd_set_value(&entry.mount, fs_opt_val);
		else if (!strcmp($1, "unmount") ||
			 !strcmp($1, "umount")) {
			if (entry.umount) {
				sprintf(msg_buf,
				    "unmount or umount may only be used once");
				amd_info(msg_buf);
				free(fs_opt_val);
				YYABORT;
			}
			entry.umount = fs_opt_val;
		} else if (!strcmp($1, "delay") ||
			   !strcmp($1, "cachedir")) {
			sprintf(msg_buf, "option %s is not used by autofs", $1);
			amd_info(msg_buf);
			free(fs_opt_val);
		} else {
			amd_notify($1);
			free(fs_opt_val);
			YYABORT;
		}
	}
	| FS_OPTION OPTION_ASSIGN
	{
		char *empty;

		empty = amd_strdup("");
		if (!empty) {
			amd_notify($1);
			YYABORT;
		}

		if (!strcmp($1, "rhost"))
			amd_set_value(&entry.rhost, empty);
		else if (!strcmp($1, "rfs"))
			amd_set_value(&entry.rfs, empty);
		else if (!strcmp($1, "dev"))
			amd_set_value(&entry.dev, empty);
		else if (!strcmp($1, "mount")) {
			amd_set_value(&entry.mount, NULL);
			free(empty);
		} else if (!strcmp($1, "umount") ||
			   !strcmp($1, "unmount")) {
			amd_set_value(&entry.umount, NULL);
			free(empty);
		} else {
			amd_notify($1);
			free(empty);
			YYABORT;
		}
	}
	| MNT_OPTION OPTION_ASSIGN options
	{
		if (!match_mnt_option_options($1, opts)) {
			amd_notify($1);
			YYABORT;
		}
		memset(opts, 0, sizeof(opts));
	}
	| MNT_OPTION OPTION_ASSIGN QUOTE options QUOTE
	{
		if (!match_mnt_option_options($1, opts)) {
			amd_notify($1);
			YYABORT;
		}
		memset(opts, 0, sizeof(opts));
	}
	| MNT_OPTION OPTION_ASSIGN
	{
		memset(opts, 0, sizeof(opts));
		if (!match_mnt_option_options($1, "")) {
			amd_notify($1);
			YYABORT;
		}
	}
	| MAP_OPTION OPTION_ASSIGN CACHE_OPTION
	{
		if (!strcmp($1, "cache")) {
			if (!match_map_option_cache_option($3))
				YYABORT;
		} else {
			amd_notify($1);
			YYABORT;
		}
	}
	;

options: OPTION
	{
		if (!strcmp($1, "fullybrowsable") ||
		    !strcmp($1, "nounmount")) {
			sprintf(msg_buf, "option %s is not currently "
					 "implemented, ignored", $1);
			amd_info(msg_buf);
		} else if (!strncmp($1, "ping=", 5) ||
			   !strncmp($1, "retry=", 6) ||
			   !strcmp($1, "public") ||
			   !strcmp($1, "softlookup") ||
			   !strcmp($1, "xlatecookie")) {
			sprintf(msg_buf, "option %s is not used by "
					 "autofs, ignored", $1);
			amd_info(msg_buf);
		} else if (!strncmp($1, "utimeout=", 9)) {
			if (entry.flags & AMD_MOUNT_TYPE_AUTO) {
				char *opt = $1;
				prepend_opt(opts, ++opt);
			} else {
				sprintf(msg_buf, "umount timeout can't be "
						 "used for other than type "
						 "\"auto\" with autofs, "
						 "ignored");
				amd_info(msg_buf);
			}
		} else
			prepend_opt(opts, $1);
	}
	| OPTION COMMA options
	{
		prepend_opt(opts, $1);
	}
	| OPTION COMMA
	{
		prepend_opt(opts, $1);
	}
	;

%%

static int match_map_option_fs_type(char *map_option, char *type)
{
	char *fs_type;

	fs_type = amd_strdup(type);
	if (!fs_type) {
		amd_notify(type);
		return 0;
	}

	if (!strcmp(fs_type, "auto"))
		entry.flags |= AMD_MOUNT_TYPE_AUTO;
	else if (!strcmp(fs_type, "nfs") ||
		 !strcmp(fs_type, "nfs4"))
		entry.flags |= AMD_MOUNT_TYPE_NFS;
	else if (!strcmp(fs_type, "nfsl"))
		entry.flags |= AMD_MOUNT_TYPE_NFSL;
	else if (!strcmp(fs_type, "link"))
		entry.flags |= AMD_MOUNT_TYPE_LINK;
	else if (!strcmp(fs_type, "linkx"))
		entry.flags |= AMD_MOUNT_TYPE_LINKX;
	else if (!strcmp(fs_type, "host"))
		entry.flags |= AMD_MOUNT_TYPE_HOST;
	else if (!strcmp(fs_type, "lofs"))
		entry.flags |= AMD_MOUNT_TYPE_LOFS;
	else if (!strcmp(fs_type, "xfs"))
		entry.flags |= AMD_MOUNT_TYPE_XFS;
	else if (!strcmp(fs_type, "ext2") ||
		   !strcmp(fs_type, "ext3") ||
		   !strcmp(fs_type, "ext4"))
		entry.flags |= AMD_MOUNT_TYPE_EXT;
	else if (!strcmp(fs_type, "program"))
		entry.flags |= AMD_MOUNT_TYPE_PROGRAM;
	else if (!strcmp(fs_type, "ufs")) {
		entry.flags |= AMD_MOUNT_TYPE_UFS;
		entry.type = conf_amd_get_linux_ufs_mount_type();
		if (!entry.type) {
			amd_msg("memory allocation error");
			amd_notify(type);
			free(fs_type);
			return 0;
		}
		free(fs_type);
		fs_type = NULL;
	} else if (!strcmp(fs_type, "cdfs")) {
		entry.flags |= AMD_MOUNT_TYPE_CDFS;
		entry.type = amd_strdup("iso9660");
		if (!entry.type) {
			amd_msg("memory allocation error");
			amd_notify(map_option);
			free(fs_type);
			return 0;
		}
		free(fs_type);
		fs_type = NULL;
	} else if (!strcmp(fs_type, "jfs") ||
		   !strcmp(fs_type, "nfsx") ||
		   !strcmp(fs_type, "lustre") ||
		   !strcmp(fs_type, "direct")) {
		sprintf(msg_buf, "file system type %s is "
				 "not yet implemented", fs_type);
		amd_msg(msg_buf);
		free(fs_type);
		return 0;
	} else if (!strcmp(fs_type, "cachefs")) {
		sprintf(msg_buf, "file system %s is not "
				 "supported by autofs, ignored",
				 fs_type);
		amd_msg(msg_buf);
		free(fs_type);
		fs_type = NULL;
	} else {
		amd_notify(fs_type);
		free(fs_type);
		return 0;
	}

	if (fs_type)
		amd_set_value(&entry.type, fs_type);

	return 1;
}

static int match_map_option_map_type(char *map_option, char *type)
{
	char *map_type;

	map_type = amd_strdup(type);
	if (!map_type) {
		amd_notify(type);
		return 0;
	}

	if (!strcmp(map_type, "file") ||
	    !strcmp(map_type, "nis") ||
	    !strcmp(map_type, "nisplus") ||
	    !strcmp(map_type, "ldap") ||
	    !strcmp(map_type, "hesiod")) {
#ifndef WITH_HESIOD
		if (!strcmp(map_type, "hesiod")) {
			amd_msg("hesiod support not built in");
			free(map_type);
			return 0;
		}
#endif
		amd_set_value(&entry.map_type, map_type);
	} else if (!strcmp(map_type, "exec")) {
		/* autofs uses "program" for "exec" map type */
		char * tmp;

		tmp = amd_strdup("program");
		if (!tmp) {
			amd_notify(type);
			free(map_type);
			return 0;
		}
		amd_set_value(&entry.map_type, tmp);
		free(map_type);
	} else if (!strcmp(map_type, "passwd")) {
		sprintf(msg_buf, "map type %s is "
				 "not yet implemented", map_type);
		amd_msg(msg_buf);
		free(map_type);
		return 0;
	} else if (!strcmp(map_type, "ndbm") ||
		   !strcmp(map_type, "union")) {
		sprintf(msg_buf, "map type %s is not "
				 "supported by autofs", map_type);
		amd_msg(msg_buf);
		free(map_type);
		return 0;
	} else {
		amd_notify(type);
		free(map_type);
		return 0;
	}

	return 1;
}

static int match_map_option_cache_option(char *type)
{
	char *cache_opt;

	cache_opt = amd_strdup(type);
	if (!cache_opt) {
		amd_notify(type);
		return 0;
	}

	if (strncmp(cache_opt, "inc", 3))
		entry.cache_opts = AMD_CACHE_OPTION_INC;
	else if (strncmp(cache_opt, "all", 3))
		entry.cache_opts = AMD_CACHE_OPTION_ALL;
	else if (strncmp(cache_opt, "re", 2))
		entry.cache_opts = AMD_CACHE_OPTION_REGEXP;
	if (strstr(cache_opt, "sync"))
		entry.cache_opts |= AMD_CACHE_OPTION_SYNC;
	free(cache_opt);

	return 1;
}

static int match_mnt_option_options(char *mnt_option, char *options)
{
	char *tmp;

	if (!strcmp(mnt_option, "opts")) {
		tmp = amd_strdup(options);
		if (!tmp)
			return 0;
		amd_set_value(&entry.opts, tmp);
	} else if (!strcmp(mnt_option, "addopts")) {
		tmp = amd_strdup(options);
		if (!tmp)
			return 0;
		amd_set_value(&entry.addopts, tmp);
	} else if (!strcmp(mnt_option, "remopts")) {
		tmp = amd_strdup(options);
		if (!tmp)
			return 0;
		amd_set_value(&entry.remopts, tmp);
	} else
		return 0;

	return 1;
}

static void prepend_opt(char *dest, char *opt)
{
	char new[MAX_OPTS_LEN];
	strcpy(new, opt);
	if (*dest != '\0') {
		strcat(new, ",");
		strcat(new, dest);
	}
	memmove(dest, new, strlen(new));
}

#if YYDEBUG
static int amd_fprintf(FILE *f, char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vsyslog(LOG_DEBUG, msg, ap);
	va_end(ap);
	return 1;
}
#endif

static char *amd_strdup(char *str)
{
	unsigned int quoted, len;
	char *tmp;

	len = strlen(str);
	quoted = 0;

	if (*str == '"') {
		quoted = 1;
		len -= 2;
	}

	tmp = strdup(str + quoted);
	if (!tmp) {
		amd_msg("memory allocation error");
		return NULL;
	} else {
		unsigned int squote;
		char *ptr;

		if (quoted) {
			if (tmp[len] != '"') {
				sprintf(msg_buf,
					"unmatched double quote near: %s", str);
				amd_info(msg_buf);
				free(tmp);
				return NULL;
			}
			tmp[len] = 0;
		}

		/* Check for matching single quotes */
		if (!strchr(tmp, 39))
			goto done;

		ptr = tmp;
		squote = 0;
		while (*ptr) {
			if (*ptr == 39)
				squote = !squote;
			ptr++;
		}
		if (squote) {
			sprintf(msg_buf,
				"unmatched single quote near: %s", str);
			amd_info(msg_buf);
			free(tmp);
			return NULL;
		}
	}
done:
	return tmp;
}

static void amd_set_value(char **field, char *value)
{
	if (*field)
		free(*field);
	*field = value;
}

static int amd_error(const char *s)
{
	if (strcmp(s, "syntax"))
		logmsg("syntax error in location near [ %s ]\n", amd_text);
	else
		logmsg("%s while parsing location.\n", s);
	return 0;
}

static int amd_notify(const char *s)
{
	logmsg("syntax error in location near [ %s ]\n", s);
	return(0);
}

static int amd_info(const char *s)
{
	info(pap->logopt, "%s\n", s);
	return 0;
}

static int amd_msg(const char *s)
{
	logmsg("%s\n", s);
	return 0;
}

static void local_init_vars(void)
{
	memset(&entry, 0, sizeof(entry));
	entry.cache_opts = AMD_CACHE_OPTION_NONE;
	memset(opts, 0, sizeof(opts));
}

static void local_free_vars(void)
{
	clear_amd_entry(&entry);
	return;
}

static void add_selector(struct selector *selector)
{
	struct selector *s = entry.selector;

	if (!s) {
		entry.selector = selector;
		return;
	}

	while (s->next)
		s = s->next;

	selector->next = s;
	entry.selector = selector;

	return;
}

static int make_selector(char *name,
			 char *value1, char *value2,
			 unsigned int compare)
{
	struct selector *s;
	char *tmp;

	if (!sel_lookup(name))
		return 0;

	s = get_selector(name);
	if (!s)
		return 0;

	if (s->sel->flags & SEL_FLAG_MACRO) {
		tmp = amd_strdup(value1);
		if (!tmp)
			goto error;
		s->comp.value = tmp;
	} else if (s->sel->flags & SEL_FLAG_FUNC1) {
		if (!value1)
			tmp = NULL;
		else {
			tmp = amd_strdup(value1);
			if (!tmp)
				goto error;
		}
		s->func.arg1 = tmp;
	} else if (s->sel->flags & SEL_FLAG_FUNC2) {
		tmp = amd_strdup(value1);
		if (!tmp)
			goto error;
		s->func.arg1 = tmp;
		if (value2) {
			tmp = amd_strdup(value2);
			if (tmp)
				s->func.arg2 = tmp;
		}
	}
	s->compare = compare;

	add_selector(s);

	return 1;
error:
	free_selector(s);
	return 0;
}

void amd_init_scan(void)
{
}

static void parse_mutex_lock(void)
{
	int status = pthread_mutex_lock(&parse_mutex);
	if (status)
		fatal(status);
	return;
}

static void parse_mutex_unlock(void *arg)
{
	int status = pthread_mutex_unlock(&parse_mutex);
	if (status)
		fatal(status);
	return;
}

static int add_location(void)
{
	struct amd_entry *new;

	new = new_amd_entry(psv);
	if (!new)
		return 0;

	if (entry.path) {
		free(new->path);
		new->path = entry.path;
	}
	new->flags = entry.flags;
	new->type = entry.type;
	new->map_type = entry.map_type;
	new->pref = entry.pref;
	new->fs = entry.fs;
	new->rhost = entry.rhost;
	new->rfs = entry.rfs;
	new->dev = entry.dev;
	new->opts = entry.opts;
	new->addopts = entry.addopts;
	new->remopts = entry.remopts;
	new->sublink = entry.sublink;
	new->mount = entry.mount;
	new->umount = entry.umount;
	new->selector = entry.selector;
	list_add_tail(&new->list, entries);
	memset(&entry, 0, sizeof(struct amd_entry));

	return 1;
}

int amd_parse_list(struct autofs_point *ap,
		   const char *buffer, struct list_head *list,
		   struct substvar **sv)
{
	char *buf;
	size_t len;
	int ret;

	len = strlen(buffer) + 2;
	buf = malloc(len);
	if (!buf)
		return 0;
	strcpy(buf, buffer);

	parse_mutex_lock();
	pthread_cleanup_push(parse_mutex_unlock, NULL);

	pap = ap;
	psv = *sv;
	entries = list;
	amd_set_scan_buffer(buf);

	local_init_vars();
	ret = amd_parse();
	local_free_vars();
	*sv = psv;

	pthread_cleanup_pop(1);
	free(buf);

	return ret;
}
