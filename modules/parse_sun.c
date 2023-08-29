/* ----------------------------------------------------------------------- *
 *   
 *  parse_sun.c - module for Linux automountd to parse a Sun-format
 *                automounter map
 * 
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *   Copyright 2004, 2005 Ian Kent <raven@themaw.net>
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
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <sys/mount.h>
#include <linux/fs.h>

#define MODULE_PARSE
#include "automount.h"

#define MODPREFIX "parse(sun): "

int parse_version = AUTOFS_PARSE_VERSION;	/* Required by protocol */

static struct mount_mod *mount_nfs = NULL;
static int init_ctr = 0;
static pthread_mutex_t parse_instance_mutex = PTHREAD_MUTEX_INITIALIZER;

static void parse_instance_mutex_lock(void)
{
	int status = pthread_mutex_lock(&parse_instance_mutex);
	if (status)
		fatal(status);
}

static void parse_instance_mutex_unlock(void)
{
	int status = pthread_mutex_unlock(&parse_instance_mutex);
	if (status)
		fatal(status);
}

extern const char *global_options;

struct parse_context {
	char *optstr;		/* Mount options */
	char *macros;		/* Map wide macro defines */
	struct substvar *subst;	/* $-substitutions */
	int slashify_colons;	/* Change colons to slashes? */
};

struct multi_mnt {
	char *path;
	char *options;
	char *location;
	struct multi_mnt *next;
};

/* Default context */

static struct parse_context default_context = {
	NULL,			/* No mount options */
	NULL,			/* No map wide macros */
	NULL,			/* The substvar local vars table */
	1			/* Do slashify_colons */
};

static char *concat_options(char *left, char *right);

/* Free all storage associated with this context */
static void kill_context(struct parse_context *ctxt)
{
	macro_lock();
	macro_free_table(ctxt->subst);
	macro_unlock();
	if (ctxt->optstr)
		free(ctxt->optstr);
	if (ctxt->macros)
		free(ctxt->macros);
	free(ctxt);
}

/* 
 * $- and &-expand a Sun-style map entry and return the length of the entry.
 * If "dst" is NULL, just count the length.
 */
int expandsunent(const char *src, char *dst, const char *key,
		 const struct substvar *svc, int slashify_colons)
{
	const struct substvar *sv;
	int len, l, seen_colons;
	const char *p;
	char ch;

	len = 0;
	seen_colons = 0;

	while ((ch = *src++)) {
		switch (ch) {
		case '&':
			l = strlen(key);
			/*
			 * In order to ensure that any isspace() characters
			 * in the key are preserved, we need to escape them
			 * here.
			 */
			const char *keyp = key;
			while (*keyp) {
				if (isspace(*keyp)) {
					if (dst) {
						*dst++ = '\\';
						*dst++ = *keyp++;
					} else
						keyp++;
					l++;
				} else {
					if (dst)
						*dst++ = *keyp++;
					else
						keyp++;
				}
			}
			len += l;
			break;

		case '$':
			if (*src == '{') {
				p = strchr(++src, '}');
				if (!p) {
					/* Ignore rest of string */
					if (dst)
						*dst = '\0';
					return len;
				}
				sv = macro_findvar(svc, src, p - src);
				if (sv) {
					l = strlen(sv->val);
					if (dst) {
						strcpy(dst, sv->val);
						dst += l;
					}
					len += l;
				}
				src = p + 1;
			} else {
				/* If the '$' is folloed by a space or NULL it
				 * can't be a macro, and the value can't be
				 * quoted since '\' and '"' cases are handled
				 * in other cases, so treat the $ as a valid
				 * map entry character.
				 */
				if (isblank(*src) || !*src) {
					if (dst)
						*dst++ = ch;
					len++;
					break;
				}
				p = src;
				while (isalnum(*p) || *p == '_')
					p++;
				sv = macro_findvar(svc, src, p - src);
				if (sv) {
					l = strlen(sv->val);
					if (dst) {
						strcpy(dst, sv->val);
						dst += l;
					}
					len += l;
				}
				src = p;
			}
			break;

		case '\\':
			len++;
			if (dst)
				*dst++ = ch;

			if (*src) {
				len++;
				if (dst)
					*dst++ = *src;
				src++;
			}
			break;

		case '"':
			len++;
			if (dst)
				*dst++ = ch;

			while (*src && *src != '"') {
				len++;
				if (dst)
					*dst++ = *src;
				src++;
			}
			if (*src) {
				len++;
				if (dst)
					*dst++ = *src;
				src++;
			}
			break;

		case ':':
			if (dst)
				*(dst++) = 
				  (seen_colons && slashify_colons) ? '/' : ':';
			len++;
			/* Were looking for the colon preceeding a path */
			if (*src == '/')
				seen_colons = 1;
			break;

		default:
			if (isspace(ch))
				seen_colons = 0;

			if (dst)
				*(dst++) = ch;
			len++;
			break;
		}
	}
	if (dst)
		*dst = '\0';
	return len;
}

static int do_init(int argc, const char *const *argv, struct parse_context *ctxt)
{
	char *noptstr, *def, *val, *macros, *gbl_options;
	char buf[MAX_ERR_BUF];
	int optlen, len, offset;
	const char *xopt;
	int i, bval;
	unsigned int append_options;

	optlen = 0;

	/* Look for options and capture, and create new defines if we need to */

	for (i = 0; i < argc; i++) {
		if (argv[i][0] == '-' &&
		   (argv[i][1] == 'D' || argv[i][1] == '-') ) {
			switch (argv[i][1]) {
			case 'D':
				if (argv[i][2])
					def = strdup(argv[i] + 2);
				else if (++i < argc)
					def = strdup(argv[i]);
				else
					break;

				if (!def) {
					char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
					logerr(MODPREFIX "strdup: %s", estr);
					break;
				}

				val = strchr(def, '=');
				if (val)
					*(val++) = '\0';
				else
					val = "";

				macro_lock();

				ctxt->subst = macro_addvar(ctxt->subst,
							def, strlen(def), val);

				macro_unlock();

				/* we use 5 for the "-D", "=", "," and the null */
				if (ctxt->macros) {
					len = strlen(ctxt->macros) + strlen(def) + strlen(val);
					macros = realloc(ctxt->macros, len + 5);
					if (!macros) {
						free(def);
						break;
					}
					strcat(macros, ",");
				} else { /* No comma, so only +4 */
					len = strlen(def) + strlen(val);
					macros = malloc(len + 4);
					if (!macros) {
						free(def);
						break;
					}
					*macros = '\0';
				}
				ctxt->macros = macros;

				strcat(ctxt->macros, "-D");
				strcat(ctxt->macros, def);
				strcat(ctxt->macros, "=");
				strcat(ctxt->macros, val);
				free(def);
				break;

			case '-':
				if (!strncmp(argv[i] + 2, "no-", 3)) {
					xopt = argv[i] + 5;
					bval = 0;
				} else {
					xopt = argv[i] + 2;
					bval = 1;
				}

				if (!strmcmp(xopt, "slashify-colons", 1))
					ctxt->slashify_colons = bval;
				else
					error(LOGOPT_ANY,
					      MODPREFIX "unknown option: %s",
					      argv[i]);
				break;

			default:
				error(LOGOPT_ANY,
				      MODPREFIX "unknown option: %s", argv[i]);
				break;
			}
		} else {
			offset = (argv[i][0] == '-' ? 1 : 0);
			len = strlen(argv[i] + offset);
			if (ctxt->optstr) {
				noptstr =
				    (char *) realloc(ctxt->optstr, optlen + len + 2);
				if (noptstr) {
					noptstr[optlen] = ',';
					strcpy(noptstr + optlen + 1, argv[i] + offset);
					optlen += len + 1;
				}
			} else {
				noptstr = (char *) malloc(len + 1);
				if (noptstr) {
					strcpy(noptstr, argv[i] + offset);
					optlen = len;
				}
			}
			if (!noptstr) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				logerr(MODPREFIX "%s", estr);
				return 1;
			}
			ctxt->optstr = noptstr;
		}
	}

	gbl_options = NULL;
	if (global_options) {
		if (ctxt->optstr && strstr(ctxt->optstr, global_options))
			goto options_done;
		gbl_options = strdup(global_options);
	}

	if (gbl_options) {
		append_options = defaults_get_append_options();
		if (append_options) {
			char *tmp;

			errno = 0;
			tmp = concat_options(gbl_options, ctxt->optstr);
			if (!tmp) {
				/* Ignore non-error NULL return */
				if (errno) {
					char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
					logerr(MODPREFIX "concat_options: %s", estr);
				}
				/* freed in concat_options */
				ctxt->optstr = NULL;
			} else
				ctxt->optstr = tmp;
		} else {
			if (!ctxt->optstr)
				ctxt->optstr = gbl_options;
			else
				free(gbl_options);
		}
	}
options_done:

	debug(LOGOPT_NONE,
	      MODPREFIX "init gathered global options: %s", ctxt->optstr);

	return 0;
}

int parse_init(int argc, const char *const *argv, void **context)
{
	struct parse_context *ctxt;
	char buf[MAX_ERR_BUF];

	*context = NULL;

	/* Set up context and escape chain */

	ctxt = (struct parse_context *) malloc(sizeof(struct parse_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	*ctxt = default_context;

	if (do_init(argc, argv, ctxt)) {
		free(ctxt);
		return 1;
	}

	/* We only need this once.  NFS mounts are so common that we cache
	   this module. */
	parse_instance_mutex_lock();
	if (mount_nfs)
		init_ctr++;
	else {
		if ((mount_nfs = open_mount("nfs", MODPREFIX))) {
			init_ctr++;
		} else {
			kill_context(ctxt);
			parse_instance_mutex_unlock();
			return 1;
		}
	}
	parse_instance_mutex_unlock();

	*context = (void *) ctxt;

	return 0;
}

int parse_reinit(int argc, const char *const *argv, void **context)
{
	struct parse_context *ctxt = (struct parse_context *) *context;
	struct parse_context *new;
	char buf[MAX_ERR_BUF];

	new = (struct parse_context *) malloc(sizeof(struct parse_context));
	if (!new) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	*new = default_context;

	if (do_init(argc, argv, new)) {
		free(new);
		return 1;
	}

	kill_context(ctxt);

	*context = (void *) new;

	return 0;
}

static const char *parse_options(const char *str, char **ret, unsigned int logopt)
{
	const char *cp = str;
	int len;

	if (*cp++ != '-')
		return str;

	if (*ret != NULL)
		free(*ret);

	len = chunklen(cp, 0);
	*ret = dequote(cp, len, logopt);

	return cp + len;
}

static char *concat_options(char *left, char *right)
{
	char buf[MAX_ERR_BUF];
	char *ret;

	if (left == NULL || *left == '\0') {
		if (!right || *right == '\0')
			return NULL;
		ret = strdup(right);
		free(right);
		return ret;
	}

	if (right == NULL || *right == '\0') {
		if (left == NULL || *left == '\0')
			return NULL;
		ret = strdup(left);
		free(left);
		return ret;
	}

	ret = malloc(strlen(left) + strlen(right) + 2);

	if (ret == NULL) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		free(left);
		free(right);
		return NULL;
	}

	strcpy(ret, left);
	strcat(ret, ",");
	strcat(ret, right);

	free(left);
	free(right);

	return ret;
}

static int sun_mount(struct autofs_point *ap, const char *root,
			const char *name, int namelen,
			const char *loc, int loclen, const char *options,
			struct parse_context *ctxt)
{
	char *fstype = "nfs";	/* Default filesystem type */
	int nonstrict = 1;
	int use_weight_only = ap->flags & MOUNT_FLAG_USE_WEIGHT_ONLY;
	int rv, cur_state;
	char *what;
	char *type;

	if (*options == '\0')
		options = NULL;

	if (options) {
		char *noptions;
		const char *comma;
		char *np;
		int len = strlen(options) + 1;

		noptions = np = alloca(len);
		*np = '\0';

		/* Extract fstype= pseudo option */
		for (comma = options; *comma != '\0';) {
			const char *cp;

			while (*comma == ',')
				comma++;

			cp = comma;

			while (*comma != '\0' && *comma != ',')
				comma++;

			if (_strncmp("fstype=", cp, 7) == 0) {
				int typelen = comma - (cp + 7);
				fstype = alloca(typelen + 1);
				memcpy(fstype, cp + 7, typelen);
				fstype[typelen] = '\0';
			} else if (_strncmp("nonstrict", cp, 9) == 0) {
				nonstrict = 1;
			} else if (_strncmp("strict", cp, 6) == 0 &&
				   comma - cp == 6) {
				nonstrict = 0;
			} else if (_strncmp("nobrowse", cp, 8) == 0 ||
				   _strncmp("browse", cp, 6) == 0 ||
				   _strncmp("timeout=", cp, 8) == 0) {
				if (strcmp(fstype, "autofs") == 0 ||
				    strstr(cp, "fstype=autofs")) {
					memcpy(np, cp, comma - cp + 1);
					np += comma - cp + 1;
				}
			} else if (_strncmp("no-use-weight-only", cp, 18) == 0) {
				use_weight_only = -1;
			} else if (_strncmp("use-weight-only", cp, 15) == 0) {
				use_weight_only = MOUNT_FLAG_USE_WEIGHT_ONLY;
			} else if (_strncmp("bg", cp, 2) == 0 ||
				   _strncmp("nofg", cp, 4) == 0) {
				continue;
			} else {
				memcpy(np, cp, comma - cp + 1);
				np += comma - cp + 1;
			}
		}

		if (np > noptions + len) {
			warn(ap->logopt, MODPREFIX "options string truncated");
			np[len] = '\0';
		} else if (np > noptions) {
			*(np - 1) = '\0';
		}

		options = noptions;
	}

	if (!strcmp(fstype, "autofs") && ctxt->macros) {
		char *noptions = NULL;

		if (!options || *options == '\0') {
			noptions = alloca(strlen(ctxt->macros) + 1);
			*noptions = '\0';
		} else {
			int len = strlen(options) + strlen(ctxt->macros) + 2;
			noptions = alloca(len);

			if (noptions) {
				strcpy(noptions, options);
				strcat(noptions, ",");
			}
		}

		if (noptions && *noptions != '\0') {
			strcat(noptions, ctxt->macros);
			options = noptions;
		} else {
			error(ap->logopt,
			      MODPREFIX "alloca failed for options");
		}
	}

	type = ap->entry->maps->type;
	if (type && !strcmp(type, "hosts")) {
		if (options && *options != '\0') {
			int len = strlen(options);
			int suid = strstr(options, "suid") ? 0 : 7;
			int dev = strstr(options, "dev") ? 0 : 6;

			if (suid || dev) {
				char *tmp = alloca(len + suid + dev + 1);
				if (!tmp) {
					error(ap->logopt, MODPREFIX
					      "alloca failed for options");
					if (nonstrict)
						return -1;
					return 1;
				}

				strcpy(tmp, options);
				if (suid)
					strcat(tmp, ",nosuid");
				if (dev)
					strcat(tmp, ",nodev");
				options = tmp;
			}
		} else {
			char *tmp = alloca(18);
			if (!tmp) {
				error(ap->logopt,
				      MODPREFIX "alloca failed for options");
				if (nonstrict)
					return -1;
				return 1;
			}
			strcpy(tmp, "nosuid,nodev");
			options = tmp;
		}
	}

	what = malloc(loclen + 1);
	if (!what) {
		char buf[MAX_ERR_BUF];
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(ap->logopt, MODPREFIX "malloc: %s", estr);
		return 1;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	if (!strcmp(fstype, "nfs") || !strcmp(fstype, "nfs4")) {
		memcpy(what, loc, loclen);
		what[loclen] = '\0';

		/* Add back "[no-]use-weight-only" for NFS mounts only */
		if (use_weight_only) {
			char *tmp;
			int len;

			if (options && *options != '\0') {
				len = strlen(options) + 19;
				tmp = alloca(len);
				strcpy(tmp, options);
				strcat(tmp, ",");
				if (use_weight_only == MOUNT_FLAG_USE_WEIGHT_ONLY)
					strcat(tmp, "use-weight-only");
				else
					strcat(tmp, "no-use-weight-only");
			} else {
				tmp = alloca(19);
				if (use_weight_only == MOUNT_FLAG_USE_WEIGHT_ONLY)
					strcpy(tmp, "use-weight-only");
				else
					strcpy(tmp, "no-use-weight-only");
			}
			options = tmp;
		}

		debug(ap->logopt, MODPREFIX
		      "mounting root %s, mountpoint %s, "
		      "what %s, fstype %s, options %s",
		      root, name, what, fstype, options);

		rv = mount_nfs->mount_mount(ap, root, name, namelen,
					    what, fstype, options, mount_nfs->context);
	} else {
		if (!loclen) {
			free(what);
			what = NULL;
		} else {
			if (*loc == ':') {
				loclen--;
				memcpy(what, loc + 1, loclen);
				what[loclen] = '\0';
			} else {
				memcpy(what, loc, loclen);
				what[loclen] = '\0';
			}
		}

		debug(ap->logopt, MODPREFIX
		      "mounting root %s, mountpoint %s, "
		      "what %s, fstype %s, options %s",
		      root, name, what, fstype, options);

		/* Generic mount routine */
		rv = do_mount(ap, root, name, namelen, what, fstype, options);
	}
	if (what)
		free(what);

	pthread_setcancelstate(cur_state, NULL);

	if (nonstrict && rv)
		return -rv;

	return rv;
}

/*
 * Scan map entry looking for evidence it has multiple key/mapent
 * pairs.
 */
static int check_is_multi(const char *mapent)
{
	const char *p = mapent;
	int multi = 0;
	int not_first_chunk = 0;

	if (!p) {
		logerr(MODPREFIX "unexpected NULL map entry pointer");
		return 0;
	}

	if (*p == '"')
		p++;

	/* If first character is "/" it's a multi-mount */
	if (*p == '/')
		return 1;

	while (*p) {
		p = skipspace(p);

		/*
		 * After the first chunk there can be additional
		 * locations (possibly not multi) or possibly an
		 * options string if the first entry includes the
		 * optional '/' (is multi). Following this any
		 * path that begins with '/' indicates a mutil-mount
		 * entry.
		 */
		if (not_first_chunk) {
			if (*p == '"')
				p++;
			/*
			 * Although an options string here would mean
			 * we have a multi-mount we can't rely on it
			 * since it's also valid in a mount location.
			 */
			if (*p == '-')
				p++;
			if (*p == '/') {
				multi = 1;
				break;
			}
		}

		while (*p == '-') {
			p += chunklen(p, 0);
			p = skipspace(p);
		}

		/*
		 * Expect either a path or location
		 * after which it's a multi mount.
		 */
		p += chunklen(p, check_colon(p));
		not_first_chunk++;
	}

	return multi;
}

static int
update_offset_entry(struct autofs_point *ap,
		    struct mapent_cache *mc, struct list_head *offsets,
		    const char *name, const char *m_root, int m_root_len,
		    const char *m_offset, const char *myoptions,
		    const char *loc, time_t age)
{
	char m_key[PATH_MAX + 1];
	char m_mapent[MAPENT_MAX_LEN + 1];
	int o_len, m_key_len, m_options_len, m_mapent_len;
	struct mapent *me;
	int ret;

	memset(m_mapent, 0, MAPENT_MAX_LEN + 1);

	if (!loc || !*loc) {
		const char *type = ap->entry->maps->type;

		/* If it's not the internal hosts map it must have a
		 * mount location.
		 */
		if (!type || strcmp(type, "hosts")) {
			error(ap->logopt,
			      MODPREFIX "syntax error in offset %s -> %s",
			      m_offset, loc);
			return CHE_FAIL;
		}
	}

	if (!*m_offset) {
		error(ap->logopt,
		      MODPREFIX "syntax error in offset %s -> %s", m_offset, loc);
		return CHE_FAIL;
	}

	o_len = strlen(m_offset);
	/* Trailing '/' causes us pain */
	if (o_len > 1) {
		while (o_len > 1 && m_offset[o_len - 1] == '/')
			o_len--;
	}
	m_key_len = m_root_len + o_len;
	if (m_key_len > PATH_MAX) {
		error(ap->logopt, MODPREFIX "multi mount key too long");
		return CHE_FAIL;
	}
	strcpy(m_key, m_root);
	strncat(m_key, m_offset, o_len);
	m_key[m_key_len] = '\0';

	m_options_len = 0;
	if (*myoptions)
		m_options_len = strlen(myoptions) + 2;

	m_mapent_len = loc ? strlen(loc) : 0;
	if (m_mapent_len + m_options_len > MAPENT_MAX_LEN) {
		error(ap->logopt, MODPREFIX "multi mount mapent too long");
		return CHE_FAIL;
	}

	if (*myoptions) {
		strcpy(m_mapent, "-");
		strcat(m_mapent, myoptions);
		if (loc) {
			strcat(m_mapent, " ");
			if (loc)
				strcat(m_mapent, loc);
		}
	} else {
		if (loc)
			strcpy(m_mapent, loc);
	}

	cache_writelock(mc);
	ret = cache_update_offset(mc, name, m_key, m_mapent, age);

	me = cache_lookup_distinct(mc, m_key);
	if (me && list_empty(&me->work)) {
		struct list_head *last;

		/* Offset entries really need to be in shortest to
		 * longest path order. If not and the list of offsets
		 * is large there will be a performace hit.
		 */
		list_for_each_prev(last, offsets) {
			struct mapent *this;

			this = list_entry(last, struct mapent, work);
			if (me->len >= this->len) {
				if (last->next == offsets)
					list_add_tail(&me->work, offsets);
				else
					list_add_tail(&me->work, last);
				break;
			}
		}
		if (list_empty(&me->work))
			list_add(&me->work, offsets);
	}
	cache_unlock(mc);

	if (ret == CHE_DUPLICATE) {
		warn(ap->logopt, MODPREFIX
		     "syntax error or duplicate offset %s -> %s", m_offset, loc);
		ret = CHE_OK;
	} else if (ret == CHE_FAIL)
		debug(ap->logopt, MODPREFIX
		      "failed to update multi-mount offset %s -> %s", m_offset, m_mapent);
	else {
		ret = CHE_OK;
		debug(ap->logopt, MODPREFIX
		      "updated multi-mount offset %s -> %s", m_offset, m_mapent);
	}

	return ret;
}

static int validate_location(unsigned int logopt, char *loc)
{
	char *ptr = loc;

	/* We don't know much about these */
	if (*ptr == ':')
		return 1;

	/* Fail on replicated entry with empty first host name */
	if (*ptr == ',') {
		error(logopt, "missing first host name in location %s", loc);
		return 0;
	}

	/*
	 * If a ':/' is present now it must be a host name, except
	 * for those special file systems like sshfs which use "#"
	 * and "@" in the host name part and ipv6 addresses that
	 * have ":", "[" and "]".
	 */
	if (!check_colon(ptr)) {
		char *esc;
		/*
		 * Don't forget cases where a colon is present but
		 * not followed by a "/" or, if there is no colon at
		 * all, we don't know if it is actually invalid since
		 * it may be a map name by itself, for example.
		 */
		if (!strchr(ptr, ':') ||
		    ((esc = strchr(ptr, '\\')) && *(esc + 1) == ':') ||
		    !strncmp(ptr, "file:", 5) || !strncmp(ptr, "yp:", 3) ||
		    !strncmp(ptr, "nis:", 4) || !strncmp(ptr, "nisplus:", 8) ||
		    !strncmp(ptr, "ldap:", 5) || !strncmp(ptr, "ldaps:", 6) ||
		    !strncmp(ptr, "sss:", 4) || !strncmp(ptr, "dir:", 4))
			return 1;
		error(logopt,
		      "expected colon delimeter not found in location %s",
		      loc);
		return 0;
	} else {
		while (*ptr && strncmp(ptr, ":/", 2)) {
			if (!(isalnum(*ptr) ||
			    *ptr == '-' || *ptr == '.' || *ptr == '_' ||
			    *ptr == ',' || *ptr == '(' || *ptr == ')' ||
			    *ptr == '#' || *ptr == '@' || *ptr == ':' ||
			    *ptr == '[' || *ptr == ']' || *ptr == '%')) {
				error(logopt, "invalid character \"%c\" "
				      "found in location %s", *ptr, loc);
				return 0;
			}

			/* Fail on replicated entry with empty host name */
			if (*ptr == ',') {
				char next = *(ptr + 1);

				if (next == ',' || next == ':') {
					error(logopt,
					      "missing host name in location %s", loc);
					return 0;
				}
			}

			ptr++;
		}

		if (*ptr && !strncmp(ptr, ":/", 2))
			ptr++;
	}

	/* Must always be something following */
	if (!*ptr) {
		error(logopt, "invalid location %s", loc);
		return 0;
	}

	return 1;
}

static int parse_mapent(const char *ent, char *g_options, char **options, char **location, int logopt)
{
	char buf[MAX_ERR_BUF];
	const char *p;
	char *myoptions, *loc;
	int l;

	p = ent;

	myoptions = strdup(g_options);
	if (!myoptions) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		error(logopt, MODPREFIX "strdup: %s", estr);
		return 0;
	}

	/* Local options are appended to per-map options */
	if (*p == '-') {
		do {
			char *tmp, *newopt = NULL;

			p = parse_options(p, &newopt, logopt);
			if (newopt && strstr(newopt, myoptions)) {
				free(myoptions);
				myoptions = newopt;
			} else if (newopt) {
				errno = 0;
				tmp = concat_options(myoptions, newopt);
				/* Ignore non-error NULL return */
				if (!tmp && errno) {
					char *estr;

					estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error(logopt, MODPREFIX
					      "concat_options: %s", estr);
					return 0;
				}
				myoptions = tmp;
			}

			p = skipspace(p);
		} while (*p == '-');
	}

	debug(logopt, MODPREFIX "gathered options: %s", myoptions);

	l = chunklen(p, check_colon(p));
	loc = dequote(p, l, logopt);
	if (!loc) {
		if (strstr(myoptions, "fstype=autofs") &&
		    strstr(myoptions, "hosts")) {
			warn(logopt, MODPREFIX "possible missing location");
			free(myoptions);
			return 0;
		}
		*options = myoptions;
		*location = NULL;
		return (p - ent);
	}

	/* Location can't begin with a '/' */
	if (*p == '/') {
		warn(logopt, MODPREFIX "error location begins with \"/\"");
		free(myoptions);
		free(loc);
		return 0;
	}

	if (!validate_location(logopt, loc)) {
		free(myoptions);
		free(loc);
		return 0;
	}

	debug(logopt, MODPREFIX "dequote(\"%.*s\") -> %s", l, p, loc);

	p += l;
	p = skipspace(p);

	while (*p && ((*p == '"' && *(p + 1) != '/') || (*p != '"' && *p != '/'))) {
		char *tmp, *ent_chunk;

		l = chunklen(p, check_colon(p));
		ent_chunk = dequote(p, l, logopt);
		if (!ent_chunk) {
			if (strstr(myoptions, "fstype=autofs") &&
			    strstr(myoptions, "hosts")) {
				warn(logopt, MODPREFIX
				     "null location or out of memory");
				free(myoptions);
				free(loc);
				return 0;
			}
			goto next;
		}

		/* Location can't begin with a '/' */
		if (*p == '/') {
			warn(logopt,
			      MODPREFIX "error location begins with \"/\"");
			free(ent_chunk);
			free(myoptions);
			free(loc);
			return 0;
		}

		if (!validate_location(logopt, ent_chunk)) {
			free(ent_chunk);
			free(myoptions);
			free(loc);
			return 0;
		}

		debug(logopt, MODPREFIX "dequote(\"%.*s\") -> %s", l, p, ent_chunk);

		tmp = realloc(loc, strlen(loc) + l + 2);
		if (!tmp) {
			error(logopt, MODPREFIX "out of memory");
			free(ent_chunk);
			free(myoptions);
			free(loc);
			return 0;
		}
		loc = tmp;

		strcat(loc, " ");
		strcat(loc, ent_chunk);

		free(ent_chunk);
next:
		p += l;
		p = skipspace(p);
	}

	*options = myoptions;
	*location = loc;

	return (p - ent);
}

static int mount_subtree(struct autofs_point *ap, struct mapent_cache *mc,
			 const char *name, char *loc, char *options, void *ctxt)
{
	struct mapent *me;
	int ret = 0, rv;

	cache_readlock(mc);
	me = cache_lookup_distinct(mc, name);
	if (!me) {
		cache_unlock(mc);
		return 0;
	}

	rv = 0;

	if (IS_MM_ROOT(me)) {
		char key[PATH_MAX + 1];
		struct mapent *ro;
		size_t len;

		len = mount_fullpath(key, PATH_MAX, ap->path, ap->len, me->key);
		if (!len) {
			warn(ap->logopt, "path loo long");
			cache_unlock(mc);
			cache_writelock(mc);
			tree_mapent_delete_offsets(mc, name);
			cache_unlock(mc);
			return 1;
		}
		key[len] = '/';
		key[len + 1] = 0;

		/* Mount root offset if it exists */
		ro = cache_lookup_distinct(me->mc, key);
		if (ro && ro->age == MM_ROOT(me)->age) {
			char *myoptions, *ro_loc;
			int namelen = name ? strlen(name) : 0;
			int ro_len;

			myoptions = NULL;
			ro_loc = NULL;

			rv = parse_mapent(ro->mapent,
				options, &myoptions, &ro_loc, ap->logopt);
			if (!rv) {
				cache_unlock(mc);
				warn(ap->logopt,
				      MODPREFIX "failed to parse root offset");
				cache_writelock(mc);
				tree_mapent_delete_offsets(mc, name);
				cache_unlock(mc);
				return 1;
			}
			ro_len = 0;
			if (ro_loc)
				ro_len = strlen(ro_loc);

			rv = sun_mount(ap, key, name, namelen, ro_loc, ro_len, myoptions, ctxt);

			free(myoptions);
			if (ro_loc)
				free(ro_loc);
		}

		if (rv <= 0) {
			ret = tree_mapent_mount_offsets(me, 1);
			if (!ret) {
				tree_mapent_cleanup_offsets(me);
				cache_unlock(mc);
				error(ap->logopt, MODPREFIX
					 "failed to mount offset triggers");
				cache_writelock(mc);
				tree_mapent_delete_offsets(mc, name);
				cache_unlock(mc);
				return 1;
			}
		}
	} else {
		int loclen = strlen(loc);
		int namelen = strlen(name);

		/* Mounts at nesting points must succeed for subtree
		 * offsets to be mounted.
		 */
		rv = sun_mount(ap, name, name, namelen, loc, loclen, options, ctxt);
		if (rv <= 0) {
			ret = tree_mapent_mount_offsets(me, 1);
			if (!ret) {
				tree_mapent_cleanup_offsets(me);
				cache_unlock(mc);
				error(ap->logopt, MODPREFIX
					 "failed to mount offset triggers");
				return 1;
			}
		}
	}
	cache_unlock(mc);

	/* strict mount failed */
	if (rv > 0)
		return rv;

	/*
	 * Convert fail on nonstrict, non-empty multi-mount
	 * to success
	 */
	if (rv < 0 && ret > 0)
		rv = 0;

	return rv;
}

static char *do_expandsunent(const char *src, const char *key,
			     const struct substvar *svc, int slashify_colons)
{
	char *mapent;
	int len;

	len = expandsunent(src, NULL, key, svc, slashify_colons);
	if (len == 0) {
		errno = EINVAL;
		return NULL;
	}
	len++;

	mapent = malloc(len);
	if (!mapent)
		return NULL;
	memset(mapent, 0, len);

	expandsunent(src, mapent, key, svc, slashify_colons);

	return mapent;
}

static void cleanup_offset_entries(struct autofs_point *ap,
				   struct mapent_cache *mc,
				   struct list_head *offsets)
{
	struct mapent *me, *tmp;
	int ret;

	if (list_empty(offsets))
		return;
	cache_writelock(mc);
	list_for_each_entry_safe(me, tmp, offsets, work) {
		list_del(&me->work);
		ret = cache_delete(mc, me->key);
		if (ret != CHE_OK)
			crit(ap->logopt, "failed to delete offset %s", me->key);
	}
	cache_unlock(mc);
}

/*
 * syntax is:
 *	[-options] location [location] ...
 *	[-options] [mountpoint [-options] location [location] ... ]...
 *
 * There are three ways this routine can be called. One where we parse
 * offsets in a multi-mount entry adding them to the cache for later lookups.
 * Another where we parse a multi-mount entry looking for a root offset mount
 * and mount it if it exists and also mount its offsets down to the first
 * level nexting point. Finally to mount non multi-mounts and to mount a
 * lower level multi-mount nesting point and its offsets.
 */
int parse_mount(struct autofs_point *ap, struct map_source *map,
		const char *name, int name_len, const char *mapent,
		void *context)
{
	struct parse_context *ctxt = (struct parse_context *) context;
	char buf[MAX_ERR_BUF];
	struct map_source *source = map;
	struct mapent_cache *mc = source->mc;
	struct mapent *me, *oe, *tmp;
	LIST_HEAD(offsets);
	char *pmapent, *options;
	const char *p;
	int mapent_len, rv = 0;
	int cur_state;
	int slashify = ctxt->slashify_colons;
	unsigned int append_options;

	if (!mapent) {
		warn(ap->logopt, MODPREFIX "error: empty map entry");
		return 1;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);

	/* Offset map entries have been expanded already, avoid expanding
	 * them again so that the quote handling is consistent between map
	 * entry locations and (previously expanded) offset map entry
	 * locations.
	 */
	if (*name == '/') {
		cache_readlock(mc);
		me = cache_lookup_distinct(mc, name);
		if (me && IS_MM(me) && !IS_MM_ROOT(me)) {
			cache_unlock(mc);
			mapent_len = strlen(mapent) + 1;
			pmapent = malloc(mapent_len + 1);
			if (!pmapent) {
				char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
				logerr(MODPREFIX "malloc: %s", estr);
				return 1;
			}
			memset(pmapent, 0, mapent_len + 1);
			strcpy(pmapent, mapent);
			goto dont_expand;
		}
		cache_unlock(mc);
	}

	macro_lock();
	ctxt->subst = addstdenv(ctxt->subst, NULL);

	pmapent = do_expandsunent(mapent, name, ctxt->subst, slashify);
	if (!pmapent) {
		error(ap->logopt, MODPREFIX "failed to expand map entry");
		ctxt->subst = removestdenv(ctxt->subst, NULL);
		macro_unlock();
		pthread_setcancelstate(cur_state, NULL);
		return 1;
	}
	mapent_len = strlen(pmapent) + 1;

	ctxt->subst = removestdenv(ctxt->subst, NULL);
	macro_unlock();

dont_expand:
	pthread_setcancelstate(cur_state, NULL);

	debug(ap->logopt, MODPREFIX "expanded entry: %s", pmapent);

	append_options = defaults_get_append_options();
	options = strdup(ctxt->optstr ? ctxt->optstr : "");
	if (!options) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		free(pmapent);
		logerr(MODPREFIX "strdup: %s", estr);
		return 1;
	}

	p = skipspace(pmapent);

	/* Deal with 0 or more options */
	if (*p == '-') {
		char *tmp, *mnt_options = NULL;

		do {
			char *noptions = NULL;

			p = parse_options(p, &noptions, ap->logopt);
			if (mnt_options && noptions && strstr(noptions, mnt_options)) {
				free(mnt_options);
				mnt_options = noptions;
			} else if (noptions) {
				errno = 0;
				tmp = concat_options(mnt_options, noptions);
				/* Ignore non-error NULL return */
				if (!tmp && errno) {
					char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error(ap->logopt,
					      MODPREFIX "concat_options: %s", estr);
					free(options);
					free(pmapent);
					return 1;
				}
				mnt_options = tmp;
			}

			p = skipspace(p);
		} while (*p == '-');

		if (options && !append_options) {
			free(options);
			options = NULL;
		}

		if (append_options) {
			if (options && mnt_options && strstr(mnt_options, options)) {
				free(options);
				options = mnt_options;
			} else if (mnt_options) {
				errno = 0;
				tmp = concat_options(options, mnt_options);
				/* Ignore non-error NULL return */
				if (!tmp && errno) {
					char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
					error(ap->logopt, MODPREFIX "concat_options: %s", estr);
					free(pmapent);
					return 1;
				}
				options = tmp;
			}
		} else
			options = mnt_options;
	}

	debug(ap->logopt, MODPREFIX "gathered options: %s", options);

	if (check_is_multi(p)) {
		char m_root[PATH_MAX + 1];
		int m_root_len;
		time_t age;
		int l;

		m_root_len = mount_fullpath(m_root, PATH_MAX, ap->path, ap->len, name);
		if (!m_root_len) {
			error(ap->logopt,
			      MODPREFIX "multi-mount root path too long");
			free(options);
			free(pmapent);
			return 1;
		}

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
		cache_readlock(mc);
		me = cache_lookup_distinct(mc, name);
		if (!me) {
			free(options);
			free(pmapent);
			cache_unlock(mc);
			pthread_setcancelstate(cur_state, NULL);
			error(ap->logopt,
			      MODPREFIX "can't find multi root %s", name);
			return 1;
		}

		/* So we know we're the multi-mount root */
		if (!IS_MM(me))
			MAPENT_SET_ROOT(me, tree_mapent_root(me))
		else {
			/*
			 * The amd host mount type assumes the lookup name
			 * is the host name for the host mount but amd uses
			 * ${rhost} for this.
			 *
			 * This introduces the possibility of multiple
			 * concurrent mount requests since constructing a
			 * mount tree that isn't under the lookup name can't
			 * take advantage of the kernel queuing of other
			 * concurrent lookups while the mount tree is
			 * constructed.
			 *
			 * Consequently multi-mount updates (currently only
			 * done for the internal hosts map which the amd
			 * parser also uses for its hosts map) can't be
			 * allowed for amd mounts.
			 */
			if (source->flags & MAP_FLAG_FORMAT_AMD) {
				free(options);
				free(pmapent);
				cache_unlock(mc);
				pthread_setcancelstate(cur_state, NULL);
				return 0;
			}
		}
		age = me->age;
		cache_unlock(mc);

		/* It's a multi-mount; deal with it */
		do {
			char *m_offset, *myoptions, *loc;
			int status;

			if ((*p == '"' && *(p + 1) != '/') || (*p != '"' && *p != '/')) {
				l = 0;
				m_offset = dequote("/", 1, ap->logopt);
				debug(ap->logopt,
				      MODPREFIX "dequote(\"/\") -> %s", m_offset);
			} else {
				l = span_space(p, mapent_len - (p - pmapent));
				m_offset = sanitize_path(p, l, LKP_MULTI, ap->logopt);
				debug(ap->logopt, MODPREFIX
				      "dequote(\"%.*s\") -> %s", l, p, m_offset);
			}

			if (!m_offset) {
				warn(ap->logopt, MODPREFIX "null path or out of memory");
				cleanup_offset_entries(ap, mc, &offsets);
				free(options);
				free(pmapent);
				pthread_setcancelstate(cur_state, NULL);
				return 1;
			}

			p += l;
			p = skipspace(p);

			myoptions = NULL;
			loc = NULL;

			l = parse_mapent(p, options, &myoptions, &loc, ap->logopt);
			if (!l) {
				cleanup_offset_entries(ap, mc, &offsets);
				free(m_offset);
				free(options);
				free(pmapent);
				pthread_setcancelstate(cur_state, NULL);
				return 1;
			}

			p += l;
			p = skipspace(p);

			status = update_offset_entry(ap, mc, &offsets,
						     name, m_root, m_root_len,
						     m_offset, myoptions, loc, age);

			if (status != CHE_OK) {
				warn(ap->logopt, MODPREFIX "error adding multi-mount");
				cleanup_offset_entries(ap, mc, &offsets);
				free(m_offset);
				free(options);
				free(pmapent);
				free(myoptions);
				if (loc)
					free(loc);
				pthread_setcancelstate(cur_state, NULL);
				return 1;
			}

			if (loc)
				free(loc);
			free(m_offset);
			free(myoptions);
		} while (*p == '/' || (*p == '"' && *(p + 1) == '/'));

		cache_writelock(mc);
		me = cache_lookup_distinct(mc, name);
		if (!me) {
			cache_unlock(mc);
			free(options);
			free(pmapent);
			cleanup_offset_entries(ap, mc, &offsets);
			pthread_setcancelstate(cur_state, NULL);
			return 1;
		}
		list_for_each_entry_safe(oe, tmp, &offsets, work) {
			if (!tree_mapent_add_node(mc, MAPENT_ROOT(me), oe))
				error(ap->logopt, "failed to add offset %s to tree", oe->key);
			list_del_init(&oe->work);
		}
		cache_unlock(mc);

		rv = mount_subtree(ap, mc, name, NULL, options, ctxt);

		free(options);
		free(pmapent);
		pthread_setcancelstate(cur_state, NULL);

		return rv;
	} else {
		/* Normal (and non-root multi-mount) entries */
		char *loc;
		int loclen;
		int l;

		/*
		 * If this is an offset belonging to a multi-mount entry
		 * it's already been parsed (above) and any option string
		 * has already been stripped so just use the remainder.
		 */
		cache_readlock(mc);
		if (*name == '/' &&
		   (me = cache_lookup_distinct(mc, name)) && IS_MM(me)) {
			cache_unlock(mc);
			loc = strdup(p);
			if (!loc) {
				free(options);
				free(pmapent);
				warn(ap->logopt, MODPREFIX "out of memory");
				return 1;
			}
			rv = mount_subtree(ap, mc, name, loc, options, ctxt);
			free(loc);
			free(options);
			free(pmapent);
			return rv;
		}
		cache_unlock(mc);

		l = chunklen(p, check_colon(p));
		loc = dequote(p, l, ap->logopt);
		if (!loc) {
			free(options);
			free(pmapent);
			warn(ap->logopt, MODPREFIX "null location or out of memory");
			return 1;
		}

		/* Location can't begin with a '/' */
		if (*p == '/') {
			free(options);
			free(pmapent);
			free(loc);
			warn(ap->logopt,
			      MODPREFIX "error location begins with \"/\"");
			return 1;
		}

		if (!validate_location(ap->logopt, loc)) {
			free(loc);
			free(options);
			free(pmapent);
			return 1;
		}

		debug(ap->logopt,
		      MODPREFIX "dequote(\"%.*s\") -> %s", l, p, loc);

		p += l;
		p = skipspace(p);

		while (*p) {
			char *tmp, *ent;

			l = chunklen(p, check_colon(p));
			ent = dequote(p, l, ap->logopt);
			if (!ent) {
				free(loc);
				free(options);
				free(pmapent);
				warn(ap->logopt,
				     MODPREFIX "null location or out of memory");
				return 1;
			}

			if (!validate_location(ap->logopt, ent)) {
				free(ent);
				free(loc);
				free(options);
				free(pmapent);
				return 1;
			}

			debug(ap->logopt,
			      MODPREFIX "dequote(\"%.*s\") -> %s", l, p, ent);

			tmp = realloc(loc, strlen(loc) + l + 2);
			if (!tmp) {
				free(ent);
				free(loc);
				free(options);
				free(pmapent);
				error(ap->logopt, MODPREFIX "out of memory");
				return 1;
			}
			loc = tmp;

			strcat(loc, " ");
			strcat(loc, ent);

			free(ent);

			p += l;
			p = skipspace(p);
		}

		/*
		 * If options are asking for a hosts map loc should be
		 * NULL but we see it can contain junk, so ....
		 */
		if ((strstr(options, "fstype=autofs") &&
		     strstr(options, "hosts"))) {
			if (loc) {
				free(loc);
				loc = NULL;
			}
			loclen = 0;
		} else {
			loclen = strlen(loc);
			if (loclen == 0) {
				free(loc);
				free(options);
				free(pmapent);
				error(ap->logopt,
				      MODPREFIX "entry %s is empty!", name);
				return 1;
			}
		}

		debug(ap->logopt,
		      MODPREFIX "core of entry: options=%s, loc=%.*s",
		      options, loclen, loc);

		if (!strcmp(ap->path, "/-"))
			rv = sun_mount(ap, name, name, name_len,
				       loc, loclen, options, ctxt);
		else
			rv = sun_mount(ap, ap->path, name, name_len,
				       loc, loclen, options, ctxt);

		if (loc)
			free(loc);
		free(options);
		free(pmapent);
		pthread_setcancelstate(cur_state, NULL);
	}
	return rv;
}

int parse_done(void *context)
{
	int rv = 0;
	struct parse_context *ctxt = (struct parse_context *) context;

	parse_instance_mutex_lock();
	if (--init_ctr == 0) {
		rv = close_mount(mount_nfs);
		mount_nfs = NULL;
	}
	parse_instance_mutex_unlock();
	if (ctxt)
		kill_context(ctxt);

	return rv;
}
