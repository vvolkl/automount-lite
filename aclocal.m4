dnl
dnl --------------------------------------------------------------------------
dnl AF_PATH_INCLUDE:
dnl
dnl Like AC_PATH_PROGS, but add to the .h file as well
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_PATH_INCLUDE,
[AC_PATH_PROGS($1,$2,$3,$4)
if test -n "$$1"; then
  AC_DEFINE(HAVE_$1,1,[define if you have $1])
  AC_DEFINE_UNQUOTED(PATH_$1, "$$1", [define if you have $1])
  HAVE_$1=1
else
  HAVE_$1=0
fi
AC_SUBST(HAVE_$1)])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_PROG:
dnl
dnl Like AC_CHECK_PROG, but fail configure if not found
dnl and only define PATH_<name> variable
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_CHECK_PROG,
[AC_PATH_PROGS($1,$2,$3,$4)
if test -n "$$1"; then
  AC_DEFINE_UNQUOTED(PATH_$1, "$$1", [define if you have $1])
  PATH_$1="$$1"
else
  AC_MSG_ERROR([required program $1 not found])
fi
AC_SUBST(PATH_$1)])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_SSS_LIB:
dnl
dnl Check if a sss autofs library exists.
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_CHECK_SSS_LIB,
[if test -z "$sssldir"; then
  AC_MSG_CHECKING(for sssd autofs library)
  for libd in /usr/lib64 /usr/lib; do
    if test -z "$sssldir"; then
      if test -e "$libd/sssd/modules/$2"; then
        sssldir=$libd/sssd/modules
      fi
    fi
  done
  if test -n "$sssldir"; then
    HAVE_$1=1
    AC_MSG_RESULT(yes)
  else
    HAVE_$1=0
    AC_MSG_RESULT(no)
  fi
fi])

dnl --------------------------------------------------------------------------
dnl AF_SLOPPY_MOUNT
dnl
dnl Check to see if mount(8) supports the sloppy (-s) option, and define
dnl the cpp variable HAVE_SLOPPY_MOUNT if so.  This requires that MOUNT is
dnl already defined by a call to AF_PATH_INCLUDE or AC_PATH_PROGS.
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_SLOPPY_MOUNT,
[if test -n "$MOUNT" ; then
  AC_MSG_CHECKING([if mount accepts the -s option])
  if "$MOUNT" -s > /dev/null 2>&1 ; then
    enable_sloppy_mount=yes
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
fi])

dnl --------------------------------------------------------------------------
dnl AF_NO_CANON_UMOUNT
dnl
dnl Check to see if umount(8) supports the no-canonicalize (-c) option, and define
dnl the cpp variable HAVE_NO_CANON_UMOUNT if so.  This requires that UMOUNT is
dnl already defined by a call to AF_PATH_INCLUDE or AC_PATH_PROGS.
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_NO_CANON_UMOUNT,
[if test -n "$UMOUNT" ; then
  AC_MSG_CHECKING([if umount accepts the -c option])
  if "$UMOUNT" -h 2>&1 | grep -e '-c.*--no-canonicalize' > /dev/null 2>&1 ; then
    enable_no_canon_umount=yes
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
fi])


dnl --------------------------------------------------------------------------
dnl AF_LINUX_PROCFS
dnl
dnl Check for the Linux /proc filesystem
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_LINUX_PROCFS,
[AC_CACHE_CHECK([for Linux proc filesystem], [ac_cv_linux_procfs],
	[ac_cv_linux_procfs=no
	 test "x`cat /proc/sys/kernel/ostype 2>&-`" = "xLinux" && ac_cv_linux_procfs=yes])
 if test $ac_cv_linux_procfs = yes
 then
	AC_DEFINE(HAVE_LINUX_PROCFS, 1,
		[Define if you have the Linux /proc filesystem.])
fi])

dnl --------------------------------------------------------------------------
dnl AF_INIT_D
dnl
dnl Check the location of the init.d directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_INIT_D,
[if test -z "$initdir"; then
  AC_MSG_CHECKING([location of the init.d directory])
  for init_d in /etc/init.d /etc/rc.d/init.d; do
    if test -z "$initdir"; then
      if test -d "$init_d"; then
	initdir="$init_d"
	AC_MSG_RESULT($initdir)
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_CONF_D
dnl
dnl Check the location of the configuration defaults directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_CONF_D,
[if test -z "$confdir"; then
  for conf_d in /etc/sysconfig /etc/defaults /etc/conf.d /etc/default; do
    if test -z "$confdir"; then
      if test -d "$conf_d"; then
	confdir="$conf_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_MAP_D
dnl
dnl Check the location of the autofs maps directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_MAP_D,
[if test -z "$mapdir"; then
  for map_d in /etc/autofs /etc; do
    if test -z "$mapdir"; then
      if test -d "$map_d"; then
	mapdir="$map_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_PID_D
dnl
dnl Check the location of the pid file directory.
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_PID_D,
[if test -z "$piddir"; then
  for pid_d in /run /var/run /tmp; do
    if test -z "$piddir"; then
      if test -d "$pid_d"; then
        piddir="$pid_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_FIFO_D
dnl
dnl Check the location of the autofs fifos directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_FIFO_D,
[if test -z "$fifodir"; then
  for fifo_d in /run /var/run /tmp; do
    if test -z "$fifodir"; then
      if test -d "$fifo_d"; then
        fifodir="$fifo_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_FLAG_D
dnl
dnl Check the location of the autofs flag file directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_FLAG_D,
[if test -z "$flagdir"; then
  for flag_d in /run /var/run /tmp; do
    if test -z "$flagdir"; then
      if test -d "$flag_d"; then
        flagdir="$flag_d"
      fi
    fi
  done
fi])

dnl ----------------------------------- ##                   -*- Autoconf -*-
dnl Check if --with-dmalloc was given.  ##
dnl From Franc,ois Pinard               ##
dnl ----------------------------------- ##
dnl
dnl Copyright (C) 1996, 1998, 1999, 2000, 2001, 2002, 2003, 2005
dnl Free Software Foundation, Inc.
dnl
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl serial 3

AC_DEFUN([AM_WITH_DMALLOC],
[AC_MSG_CHECKING([if malloc debugging is wanted])
AC_ARG_WITH(dmalloc,
[  --with-dmalloc          use dmalloc, as in
			  http://www.dmalloc.com/dmalloc.tar.gz],
[if test "$withval" = yes; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(WITH_DMALLOC,1,
	    [Define if using the dmalloc debugging malloc package])
  DMALLOCLIB="-ldmallocth"
  LDFLAGS="$LDFLAGS -g"
else
  AC_MSG_RESULT(no)
fi], [AC_MSG_RESULT(no)])
])

dnl --------------------------------------------------------------------------
dnl AF_WITH_SYSTEMD
dnl
dnl Check the location of the systemd unit files directory
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_WITH_SYSTEMD],
[AC_ARG_WITH(systemd,
[  --with-systemd@<:@=systemddir@:>@  install systemd unit file.  If 'yes'
			  probe the system for unit directory.
			  If a path is specified, assume that
			  is a valid install path.],
[if test "$withval" = yes; then
  if test -z "$systemddir"; then
    AC_MSG_CHECKING([location of the systemd unit files directory])
    for systemd_d in /usr/lib/systemd/system /usr/lib64/systemd/system /lib/systemd/system /lib64/systemd/system; do
      if test -z "$systemddir"; then
        if test -d "$systemd_d"; then
          systemddir="$systemd_d"
        fi
      fi
    done
  fi
  WITH_SYSTEMD=0
  if test -n "$systemddir"; then
    AC_MSG_RESULT($systemddir)
    WITH_SYSTEMD=1
  else
    AC_MSG_RESULT(not found)
  fi
else
 if test "$withval" != no; then
  systemddir=$withval
  WITH_SYSTEMD=1
 fi
fi])
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_KRB5
dnl
dnl Check for Kerberos 5
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_KRB5],
[AC_PATH_PROGS(KRB5_CONFIG, krb5-config, no)
AC_MSG_CHECKING(for Kerberos library)
if test "$KRB5_CONFIG" = "no"
then
  AC_MSG_RESULT(no)
  HAVE_KRB5=0
else
  AC_MSG_RESULT(yes)
  HAVE_KRB5=1
  KRB5_LIBS=`$KRB5_CONFIG --libs`
  KRB5_FLAGS=`$KRB5_CONFIG --cflags`

  SAVE_CFLAGS=$CFLAGS
  SAVE_LIBS=$LIBS
  CFLAGS="$CFLAGS $KRB5_FLAGS"
  LIBS="$LIBS $KRB5_LIBS"

  AC_CHECK_FUNCS([krb5_principal_get_realm])

  CFLAGS="$SAVE_CFLAGS"
  LIBS="$SAVE_LIBS"
fi])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_LIBHESIOD
dnl
dnl Check for lib hesiod
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_LIBHESIOD],
[AC_MSG_CHECKING(for libhesiod)

# save current libs
af_check_hesiod_save_libs="$LIBS"
LIBS="$LIBS -lhesiod -lresolv"

AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([[ #include <hesiod.h> ]],
  [[ void *c; hesiod_init(&c); ]])],
  [ HAVE_HESIOD=1
    LIBHESIOD="$LIBHESIOD -lhesiod -lresolv"
    AC_MSG_RESULT(yes) ],
  [ AC_MSG_RESULT(no) ])

# restore libs
LIBS="$af_check_hesiod_save_libs"
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_FUNC_LDAP_SUPPORT_SASL
dnl
dnl Check for sasl support in ldap
dnl --------------------------------------------------------------------------
AC_DEFUN(
  [AF_CHECK_FUNC_LDAP_SUPPORT_SASL],
  [AC_MSG_CHECKING(for cyrus sasl support in openldap)
    have_openldap_cyrus_sasl=no
    # save current libs
    af_check_ldap_support_sasl_save_libs="$LIBS"
    LIBS="$LIBLDAP"

    AC_RUN_IFELSE(
      [ AC_LANG_SOURCE(
        [ #include <stdlib.h>
          #include <ldap.h>
          int main (int argc, char **argv) {
            LDAP *ldap = NULL;
            int lret = 0;

            lret = ldap_initialize(&ldap, NULL);
            if (lret != LDAP_OPT_SUCCESS) {
              exit(1);
            }
            lret = ldap_set_option(ldap, LDAP_OPT_X_SASL_NOCANON,
                                   LDAP_OPT_ON);
            exit(lret == LDAP_OPT_SUCCESS ? 0 : 1);
          } ])],
      have_openldap_sasl=yes,
      have_openldap_sasl=no,
      have_openldap_sasl=yes)

    AC_MSG_RESULT($have_openldap_sasl)
    if test "$have_openldap_sasl" = "yes"; then
      AC_DEFINE(WITH_LDAP_CYRUS_SASL,1,
         [Define if OpenLDAP was built with Cyrus SASL])
    fi

    # restore libs
    LIBS="$af_check_ldap_parse_page_control_save_libs"
  ])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_FUNC_LDAP_CREATE_PAGE_CONTROL
dnl
dnl Check for function ldap_create_page_control
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_FUNC_LDAP_CREATE_PAGE_CONTROL],
[AC_MSG_CHECKING(for ldap_create_page_control in -lldap)

# save current libs
af_check_ldap_create_page_control_save_libs="$LIBS"
LIBS="$LIBS -lldap"
af_check_ldap_create_page_control_save_cflags="$CFLAGS"
CFLAGS="$CFLAGS -Werror=implicit-function-declaration"

AC_LINK_IFELSE(
  [ AC_LANG_PROGRAM([[ #include <ldap.h> ]],
  [[ LDAP *ld;
    ber_int_t ps;
    struct berval *c;
    int ic, ret;
    LDAPControl **clp;
    ret = ldap_create_page_control(ld,ps,c,ic,clp); ]])],
  [ af_have_ldap_create_page_control=yes
    AC_MSG_RESULT(yes) ],
  [ AC_MSG_RESULT(no) ])

if test "$af_have_ldap_create_page_control" = "yes"; then
  AC_DEFINE(HAVE_LDAP_CREATE_PAGE_CONTROL, 1,
        [Define to 1 if you have the `ldap_create_page_control' function.])
fi

# restore libs
LIBS="$af_check_ldap_create_page_control_save_libs"
CFLAGS="$af_check_ldap_create_page_control_save_cflags"
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_FUNC_LDAP_PARSE_PAGE_CONTROL
dnl
dnl Check for function ldap_parse_page_control
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_FUNC_LDAP_PARSE_PAGE_CONTROL],
[AC_MSG_CHECKING(for ldap_parse_page_control in -lldap)

# save current libs
af_check_ldap_parse_page_control_save_libs="$LIBS"
LIBS="$LIBS -lldap"
af_check_ldap_parse_page_control_save_cflags="$CFLAGS"
CFLAGS="$CFLAGS -Werror=implicit-function-declaration"

AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
   [[ #define LDAP_DEPRECATED 1
      #include <ldap.h> ]],
   [[ LDAP *ld;
      ber_int_t *ct;
      struct berval *c;
      int ret;
      LDAPControl **clp;
      ret = ldap_parse_page_control(ld,clp,ct,c); ]])],
  [ af_have_ldap_parse_page_control=yes
    AC_MSG_RESULT(yes) ],
  [ AC_MSG_RESULT(no) ])

if test "$af_have_ldap_create_page_control" = "yes"; then
  AC_DEFINE(HAVE_LDAP_PARSE_PAGE_CONTROL, 1,
        [Define to 1 if you have the `ldap_parse_page_control' function.])
fi

# restore libs
LIBS="$af_check_ldap_parse_page_control_save_libs"
CFLAGS="$af_check_ldap_parse_page_control_save_cflags"
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_YPCLNT_HEADER
dnl
dnl Check for include file rpcsvc/ypclnt.h for YellowPages support.
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_YPCLNT_HEADER],
[
# save current CFLAGS
af_check_ypclnt_header_save_cflags="$CFLAGS"
CFLAGS="$CFLAGS $NSL_CFLAGS $TIRPC_CFLAGS"

HAVE_YPCLNT=0
AC_CHECK_HEADER([rpcsvc/ypclnt.h], HAVE_YPCLNT=1)
AC_SUBST(HAVE_YPCLNT)
if test "$HAVE_YPCLNT" = "1"; then
	AC_DEFINE(HAVE_YPCLNT, 1,
		[Define if using YellowPages])
fi

# restore libs
CFLAGS="$af_check_ypclnt_header_save_cflags"
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_NIS_HEADER
dnl
dnl Check for include file rpcsvc/nis.h for NIS+ support.
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_NIS_HEADER],
[
# save current CFLAGS
af_check_nis_header_save_cflags="$CFLAGS"
CFLAGS="$CFLAGS $NSL_CFLAGS $TIRPC_CFLAGS"

HAVE_NISPLUS=0
AC_CHECK_HEADER([rpcsvc/nis.h], HAVE_NISPLUS=1)
AC_SUBST(HAVE_NISPLUS)
if test "$HAVE_NISPLUS" = "1"; then
	AC_DEFINE(HAVE_NISPLUS, 1,
		[Define if using NIS+])
fi

# restore libs
CFLAGS="$af_check_nis_header_save_cflags"
])
