/* include/config.h.  Generated from config.h.in by configure.  */
/* include/config.h.in.  Generated from configure.ac by autoheader.  */

/* leave this alone */
#define ENABLE_EXT_ENV 1

/* Enable forced shutdown on USR1 signal */
/* #undef ENABLE_FORCED_SHUTDOWN */

/* Enable exit, ignoring busy mounts */
/* #undef ENABLE_IGNORE_BUSY_MOUNTS */

/* Enable limit stack use of getgrgid_r() */
/* #undef ENABLE_LIMIT_GETGRGID_SIZE */

/* Disable use of locking when spawning mount command */
#define ENABLE_MOUNT_LOCKING 1

/* Enable static build with minimal dependencies */
#define ENABLE_STATIC_BUILD 1

/* define if you have E2FSCK */
#define HAVE_E2FSCK 1

/* define if you have E3FSCK */
#define HAVE_E3FSCK 1

/* define if you have E4FSCK */
#define HAVE_E4FSCK 1

/* Define to 1 if you have the `getrpcbyname' function. */
/* #undef HAVE_GETRPCBYNAME */

/* Define to 1 if you have the `getservbyname' function. */
/* #undef HAVE_GETSERVBYNAME */

/* Define to 1 if you have the `innetgr' function. */
#define HAVE_INNETGR 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `krb5_principal_get_realm' function. */
/* #undef HAVE_KRB5_PRINCIPAL_GET_REALM */

/* Define to 1 if you have the `ldap_create_page_control' function. */
/* #undef HAVE_LDAP_CREATE_PAGE_CONTROL */

/* Define to 1 if you have the `ldap_parse_page_control' function. */
/* #undef HAVE_LDAP_PARSE_PAGE_CONTROL */

/* Define if you have the Linux /proc filesystem. */
#define HAVE_LINUX_PROCFS 1

/* define if you have MOUNT */
#define HAVE_MOUNT 1

/* define if you have MOUNT_NFS */
#define HAVE_MOUNT_NFS 1

/* Define if using NIS+ */
#define HAVE_NISPLUS 1

/* define if the umount command supports the -c option */
#define HAVE_NO_CANON_UMOUNT 1

/* Define to 1 if you have the `pipe2' function. */
#define HAVE_PIPE2 1

/* define if the mount command supports the -s option */
#define HAVE_SLOPPY_MOUNT 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* define if you have UMOUNT */
#define HAVE_UMOUNT 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define if using YellowPages */
#define HAVE_YPCLNT 1

/* Use libxml2 tsd usage workaround */
#define LIBXML2_WORKAROUND 1

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* define if you have E2FSCK */
#define PATH_E2FSCK "/usr/sbin/fsck.ext2"

/* define if you have E3FSCK */
#define PATH_E3FSCK "/usr/sbin/fsck.ext3"

/* define if you have E4FSCK */
#define PATH_E4FSCK "/usr/sbin/fsck.ext4"

/* define if you have LEX */
#define PATH_LEX "/usr/bin/flex"

/* define if you have MOUNT */
#define PATH_MOUNT "/usr/bin/mount"

/* define if you have MOUNT_NFS */
#define PATH_MOUNT_NFS "/usr/sbin/mount.nfs"

/* define if you have RANLIB */
#define PATH_RANLIB "/usr/bin/ranlib"

/* define if you have UMOUNT */
#define PATH_UMOUNT "/usr/bin/umount"

/* define if you have YACC */
#define PATH_YACC "/usr/bin/bison"

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Define to 1 to use the libtirpc tsd usage workaround */
/* #undef TIRPC_WORKAROUND */

/* Define if your C library does not provide versionsort */
/* #undef WITHOUT_VERSIONSORT */

/* Define if using the dmalloc debugging malloc package */
/* #undef WITH_DMALLOC */

/* Define if using Hesiod as a source of automount maps */
/* #undef WITH_HESIOD */

/* Define if using LDAP as a source of automount maps */
/* #undef WITH_LDAP */

/* Define if OpenLDAP was built with Cyrus SASL */
/* #undef WITH_LDAP_CYRUS_SASL */

/* Define to 1 if you have the libtirpc library installed */
/* #undef WITH_LIBTIRPC */

/* Define if using SASL authentication with the LDAP module */
/* #undef WITH_SASL */
