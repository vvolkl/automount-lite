#
# configure.ac for the autofs daemon

AC_PREREQ(2.5)

#
# Disable caching (the script is tiny, and it doesn't work with --with-path)
# then start autofs
#
define([AC_CACHE_LOAD], )dnl
define([AC_CACHE_SAVE], )dnl
AC_INIT(.autofs-5.1.9)

# for pkg-config macros
m4_include([/usr/share/aclocal/pkg.m4])

#
# autofs installs by default in /usr
#
AC_PREFIX_DEFAULT(/usr)

#
# The user can specify --with-path=PATH rather than relying on the default
#
searchpath="/usr/bin:/bin:/usr/sbin:/sbin"
AC_ARG_WITH(path,
[  --with-path=PATH	  look in PATH for binaries needed by the automounter],
	if test -z "$withval" -o "$withval" = "yes" -o "$withval" = "no"
	then
		:
	else
		searchpath="${withval}"
	fi
)

AC_MSG_CHECKING([for binaries in])
AC_MSG_RESULT([$searchpath])

#
# Make sure we have "/proc"
#
AF_LINUX_PROCFS()

#
# Location of init.d directory?
#
AF_INIT_D()
AC_SUBST(initdir)
AF_PID_D()
AC_SUBST(piddir)
PKG_PROG_PKG_CONFIG

#
# Check for systemd unit files direectory exists if unit file installation
# is requested
#
AF_WITH_SYSTEMD()
AC_SUBST(systemddir)
AC_SUBST(WITH_SYSTEMD)
PKG_CHECK_MODULES([systemd],[libsystemd],,
[
  AC_CHECK_LIB(systemd, sm_notify, systemd_LIBS="-lsystemd")
  AC_SUBST(systemd_LIBS)
])

#
# Location of system config script directory?
#
AF_CONF_D()
AC_ARG_WITH(confdir,
[  --with-confdir=DIR	  use DIR for autofs configuration files],
	if test -z "$withval" -o "$withval" = "yes" -o "$withval" = "no"
	then
		:
	else
		confdir="${withval}"
	fi
)
AC_MSG_CHECKING([for autofs configuration file directory])
AC_MSG_RESULT([$confdir])
AC_SUBST(confdir)

#
# The user can specify --with-mapsdir=PATH to specify autofs maps go
#
AF_MAP_D()
AC_ARG_WITH(mapdir,
[  --with-mapdir=PATH	  look in PATH for mount maps used by the automounter],
	if test -z "$withval" -o "$withval" = "yes" -o "$withval" = "no"
	then
		:
	else
		mapdir="${withval}"
	fi
)
AC_MSG_CHECKING([for autofs maps directory])
AC_MSG_RESULT([$mapdir])
AC_SUBST(mapdir)

#
# The user can specify --with-fifodir=PATH to specify where autofs fifos go
#
AF_FIFO_D()
AC_ARG_WITH(fifodir,
[  --with-fifodir=PATH	   use PATH as the directory for fifos used by the automounter],
	if test -z "$withval" -o "$withval" = "yes" -o "$withval" = "no"
	then
		:
	else
		fifodir="${withval}"
	fi
)
AC_MSG_CHECKING([for autofs fifos directory])
AC_MSG_RESULT([$fifodir])
AC_SUBST(fifodir)

#
# The user can specify --with-flagdir=PATH to specify where autofs flag file goes
#
AF_FLAG_D()
AC_ARG_WITH(flagdir,
[  --with-flagdir=PATH	   use PATH as the directory for the flag file used by the automounter],
	if test -z "$withval" -o "$withval" = "yes" -o "$withval" = "no"
	then
		:
	else
		flagdir="${withval}"
	fi
)
AC_MSG_CHECKING([for autofs flag file directory])
AC_MSG_RESULT([$flagdir])
AC_SUBST(flagdir)

#
# Use libtirpc
#
AC_ARG_WITH([libtirpc], AS_HELP_STRING([--with-libtirpc], [use libtirpc if available]))
if test "x$with_libtirpc" = "xyes"; then
  PKG_CHECK_MODULES([TIRPC],[libtirpc],[
		AC_DEFINE(WITH_LIBTIRPC,1,
			[Define to 1 if you have the libtirpc library installed])
		AC_DEFINE(TIRPC_WORKAROUND,1,
			[Define to 1 to use the libtirpc tsd usage workaround])
    ])
  AC_CHECK_FUNCS([getrpcbyname getservbyname])
fi

#
# Optional include dmalloc
#
AM_WITH_DMALLOC()
AC_SUBST(DMALLOCLIB)

#
# Programs needed for various system functions or modules
#
AF_PATH_INCLUDE(MOUNT, mount, /bin/mount, $searchpath)
AF_PATH_INCLUDE(MOUNT_NFS, mount.nfs, /sbin/mount.nfs , $searchpath)
AF_PATH_INCLUDE(UMOUNT, umount, /bin/umount, $searchpath)
AF_PATH_INCLUDE(E2FSCK, fsck.ext2 e2fsck, , $searchpath)
AF_PATH_INCLUDE(E3FSCK, fsck.ext3 e3fsck, , $searchpath)
AF_PATH_INCLUDE(E4FSCK, fsck.ext4 e4fsck, , $searchpath)

AF_CHECK_PROG(LEX, flex lex, , $searchpath)
AF_CHECK_PROG(YACC, bison, , $searchpath)
AF_CHECK_PROG(RANLIB, ranlib, , $searchpath)

AF_CHECK_SSS_LIB(SSS_AUTOFS, libsss_autofs.so)
AC_SUBST(HAVE_SSS_AUTOFS)
AC_SUBST(sssldir)

AC_CHECK_FUNCS(pipe2 innetgr)

#
# Newer mounts have the -s (sloppy) option to ignore unknown options,
# good for portability
#
AC_ARG_ENABLE(sloppy-mount,
[  --enable-sloppy-mount         enable the use of the -s option to mount],,
	enable_sloppy_mount=auto)
if test x$enable_sloppy_mount = xauto; then
	AF_SLOPPY_MOUNT()
fi
if test x$enable_sloppy_mount = xyes; then
	AC_DEFINE(HAVE_SLOPPY_MOUNT, 1, [define if the mount command supports the -s option])
fi

#
# Newer umounts have the -c (--no-canonicalize) option to avoid
# stating the path and possible blocking.  Good for NFS.
#
AC_ARG_ENABLE(no-canon-umount,
[  --enable-no-canon-umount         enable the use of the -c option to umount],,
	enable_no_canon_umount=auto)
if test x$enable_no_canon_umount = xauto; then
	AF_NO_CANON_UMOUNT()
fi
if test x$enable_no_canon_umount = xyes; then
	AC_DEFINE(HAVE_NO_CANON_UMOUNT, 1, [define if the umount command supports the -c option])
fi

ENABLE_FEDFS=""
AC_ARG_ENABLE(fedfs,
[  --enable-fedfs                enable inclusion of fedfs binaries mount.fedfs and fedfs-map-nfs4],,
	enable_fedfs=no)
if test x$enable_fedfs = xyes; then
	ENABLE_FEDFS="1"
fi
AC_SUBST(ENABLE_FEDFS)

# LDAP SASL auth needs libxml and Kerberos
PKG_CHECK_MODULES([XML], [libxml-2.0], [
  HAVE_LIBXML=1
  AC_DEFINE(LIBXML2_WORKAROUND, 1, [Use libxml2 tsd usage workaround])
], [HAVE_LIBXML=0])

AF_CHECK_KRB5()

AC_SEARCH_LIBS([versionsort],[])
if test "$ac_cv_search_versionsort" = "no"; then
	AC_DEFINE(WITHOUT_VERSIONSORT, 1,
		[Define if your C library does not provide versionsort])
fi

# glibc < 2.17 needs librt for clock_gettime()
AC_CHECK_LIB(rt, clock_gettime, LIBCLOCK_GETTIME="-lrt")
AC_SUBST(LIBCLOCK_GETTIME)

PKG_CHECK_MODULES([NSL],[libnsl],,
[
AC_CHECK_LIB(nsl, yp_match, NSL_LIBS="-lnsl")
AC_SUBST(NSL_LIBS)
NSL_CFLAGS=""
])

AC_CHECK_LIB(resolv, res_query, LIBRESOLV="-lresolv", AC_CHECK_LIB(resolv, __res_query, LIBRESOLV="-lresolv"))
AC_SUBST(LIBRESOLV)

#
# Hesiod support?  Expect that this may have a special directory...
#
AF_tmp_ldflags="$LDFLAGS"
LIBHESIOD=''
HAVE_HESIOD=''
AC_ARG_WITH(hesiod,
[  --with-hesiod=DIR	  enable Hesiod support (libs and includes in DIR)],
	if test "$withval" = no
	then
		HAVE_HESIOD=0	# Disable
	elif test -z "$withval" -o "$withval" = 'yes'
	then
		: Search for Hesiod in normal directory path
	else
		: Search for Hesiod in specific directory
		LDFLAGS="$LDFLAGS -L${withval}/lib"
		LIBHESIOD="-L${withval}/lib"
		HESIOD_FLAGS="-I${withval}/include"
	fi
)	

if test -z "$HAVE_HESIOD" -o "$HAVE_HESIOD" != "0"
then
	HAVE_HESIOD=0
	AF_CHECK_LIBHESIOD()
	if test "$HAVE_HESIOD" = "1"; then
		AC_DEFINE(WITH_HESIOD,1,
			[Define if using Hesiod as a source of automount maps])
	fi
fi
AC_SUBST(HAVE_HESIOD)
AC_SUBST(LIBHESIOD)
AC_SUBST(HESIOD_FLAGS)
LDFLAGS="${AF_tmp_ldflags}"

AF_CHECK_YPCLNT_HEADER()
AF_CHECK_NIS_HEADER()

#
# OpenLDAP support?  Expect that this may have a special directory...
#
AF_tmp_ldflags="$LDFLAGS"
AF_tmp_libs="$LIBS"
LIBLDAP=''
HAVE_LDAP=''
AC_ARG_WITH(openldap,
[  --with-openldap=DIR	  enable OpenLDAP map support (libs and includes in DIR)],
	if test "$withval" = 'no'; then
		HAVE_LDAP=0	# Disable 
	elif test -z "$withval" -o "$withval" = 'yes'
	then
		: Search for LDAP in normal directory path
	else
		: Search for LDAP in specific directory
		LDFLAGS="$LDFLAGS -L${withval}/lib"
		LIBLDAP="-L${withval}/lib"
		LDAP_FLAGS="-I${withval}/include"
	fi
)
if test -z "$HAVE_LDAP" -o "$HAVE_LDAP" != "0"; then
	HAVE_LDAP=0
	LDAP_FLAGS="$LDAP_FLAGS -DLDAP_DEPRECATED=1"
	AC_CHECK_LIB(ldap, ldap_initialize, HAVE_LDAP=1 LIBLDAP="$LIBLDAP -lldap -llber -lresolv", ,
		     -llber -lresolv $LIBS)
	if test "$HAVE_LDAP" = "1"; then
		AC_DEFINE(WITH_LDAP,1,
			[Define if using LDAP as a source of automount maps])
	AF_CHECK_FUNC_LDAP_SUPPORT_SASL()
	AF_CHECK_FUNC_LDAP_CREATE_PAGE_CONTROL()
	AF_CHECK_FUNC_LDAP_PARSE_PAGE_CONTROL()
    fi
fi

AC_SUBST(LDAP_FLAGS)
AC_SUBST(HAVE_LDAP)
AC_SUBST(LIBLDAP)
LDFLAGS="${AF_tmp_ldflags}"
LIBS="${AF_tmp_libs}"

#
# SASL support
#   configure magic taken from:
#	http://www.timof.qipc.org/autofs/autofs-4.1.4-ldap-20050930.patch
#

AF_tmp_ldflags="$LDFLAGS"
LIBSASL=''
HAVE_SASL=''
AC_ARG_WITH(sasl,
[  --with-sasl=DIR	  enable SASL support for LDAP maps (libs and includes in DIR)],
	if test "$withval" = 'no'; then
		HAVE_SASL=0     # Disable
	elif test -z "$withval" -o "$withval" = 'yes'
	then
		: Search for SASL in normal directory path
	else
		: Search for SASL in specific directory
		HAVE_SASL=1
		LDFLAGS="$LDFLAGS -L${withval}/lib"
		LIBSASL="-L${withval}/lib"
		SASL_FLAGS="-I${withval}/include"
	fi
)
if test -z "$HAVE_SASL" -o "$HAVE_SASL" != "0" -a "$HAVE_LIBXML" = "1"
then
	HAVE_SASL=0
	AC_CHECK_LIB(sasl2, sasl_client_start, HAVE_SASL=1 LIBSASL="$LIBSASL -lsasl2", , -lsasl2 $LIBS)
	if test "$HAVE_SASL" = "1"; then
		AC_DEFINE(WITH_SASL,1,
			[Define if using SASL authentication with the LDAP module])
	fi
fi

AC_SUBST(XML_CFLAGS)
AC_SUBST(XML_LIBS)
AC_SUBST(SASL_FLAGS)
AC_SUBST(HAVE_SASL)
AC_SUBST(LIBSASL)
AC_SUBST(KRB5_LIBS)
AC_SUBST(KRB5_FLAGS)
LDFLAGS="${AF_tmp_ldflags}"

#
# Does gcc support building position independent executables?
#
AC_PROG_CC
cat > pietest.c <<EOF
int main(void) { return 0; }
EOF
CFLAGS=-fPIE
LDFLAGS=-pie
DAEMON_CFLAGS=
DAEMON_LDFLAGS=
AC_MSG_CHECKING([whether gcc -fPIE works])
AC_RUN_IFELSE([AC_LANG_PROGRAM([[]], [[int main(void) {return 0;}]])],
	      [gcc_supports_pie=yes], [gcc_supports_pie=no], [gcc_supports_pie=no])
AC_MSG_RESULT([$gcc_supports_pie])
if test $gcc_supports_pie = yes ; then
	DAEMON_CFLAGS="-fPIE"
	DAEMON_LDFLAGS="-pie"
fi
rm -f pietest.c
AC_SUBST(DAEMON_CFLAGS)
AC_SUBST(DAEMON_LDFLAGS)

#
# Enable ability to access value in external env variable
#
AC_ARG_ENABLE(ext-env,
[  --disable-ext-env	        disable search in environment for substitution variable],,
	enableval=yes)
if test x$enable_ext_env = xyes -o x$enableval = xyes; then
        AC_DEFINE(ENABLE_EXT_ENV, 1, [leave this alone])
fi

#
# Disable use of locking when spawning mount command
#
AC_ARG_ENABLE(mount-locking,
[  --disable-mount-locking       disable use of locking when spawning mount command],,
	enableval=yes)
if test x$enable_mount_locking = xyes -o x$enableval = xyes; then
	AC_DEFINE(ENABLE_MOUNT_LOCKING, 1, [Disable use of locking when spawning mount command])
fi

#
# Enable forced shutdown on USR1 signal (unlink umounts all mounts).
#
AC_ARG_ENABLE(force-shutdown,
[  --enable-force-shutdown       enable USR1 signal to force unlink umount of any
			        busy mounts during shutdown],,
	enableval=no)
if test x$enable_force_shutdown = xyes -o x$enableval = xyes; then
	AC_DEFINE(ENABLE_FORCED_SHUTDOWN, 1, [Enable forced shutdown on USR1 signal])
fi

#
# Enable exit, ignoring busy mounts.
#
AC_ARG_ENABLE(ignore-busy,
[  --enable-ignore-busy	        enable exit without umounting busy mounts during
			        shutdown],,
	enableval=no)
if test x$enable_ignore_busy_mounts = xyes -o x$enableval = xyes; then
	AC_DEFINE(ENABLE_IGNORE_BUSY_MOUNTS, 1, [Enable exit, ignoring busy mounts])
fi

#
# Enable exit, ignoring busy mounts.
#
AC_ARG_ENABLE(limit-getgrgid-size,
[  --enable-limit-getgrgid-size	enable limit stack use of getgrgid_r()],,
	enableval=no)
if test x$enable_limit_getgrgid_size = xyes -o x$enableval = xyes; then
	AC_DEFINE(ENABLE_LIMIT_GETGRGID_SIZE, 1, [Enable limit stack use of getgrgid_r()])
fi

#
# Write Makefile.conf and include/config.h
#
AC_CONFIG_HEADERS(include/config.h)
AC_CONFIG_FILES(Makefile.conf)
AC_OUTPUT()

#
# Run make clean since we don't explicitly code the header file dependencies
#
AC_CONFIG_COMMANDS(foo, [make clean])
