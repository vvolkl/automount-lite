#
# Makefile for autofs
#

-include ../Makefile.conf
include ../Makefile.rules

ifeq ($(STATIC), 1)
# For static builds, exclude modules that require external dependencies
SRCS :=	lookup_file.c lookup_program.c lookup_userhome.c \
	lookup_multi.c lookup_dir.c \
	parse_sun.c \
	mount_generic.c mount_autofs.c mount_bind.c

MODS :=	lookup_file.so lookup_program.so lookup_userhome.so \
	lookup_multi.so lookup_dir.so \
	parse_sun.so \
	mount_generic.so mount_autofs.so mount_bind.so
else
# Full build with all modules
SRCS :=	lookup_file.c lookup_program.c  lookup_userhome.c \
	lookup_multi.c lookup_hosts.c lookup_dir.c \
	parse_sun.c parse_amd.c \
	mount_generic.c  mount_nfs.c  mount_afs.c  mount_autofs.c \
	mount_changer.c  mount_bind.c

MODS :=	lookup_file.so lookup_program.so lookup_userhome.so \
	lookup_multi.so lookup_hosts.so lookup_dir.so \
	parse_sun.so parse_amd.so \
	mount_generic.so mount_nfs.so mount_afs.so mount_autofs.so \
	mount_changer.so mount_bind.so
endif

YACCSRC = amd_tok.c amd_parse.tab.c amd_parse.tab.h

ifeq ($(EXT2FS), 1)
  SRCS += mount_ext2.c
  MODS += mount_ext2.so
else
 ifeq ($(EXT3FS), 1)
   SRCS += mount_ext2.c
   MODS += mount_ext2.so
 endif
endif

ifeq ($(HESIOD), 1)
  SRCS += lookup_hesiod.c  parse_hesiod.c
  MODS += lookup_hesiod.so parse_hesiod.so
endif

ifeq ($(NISPLUS), 1)
  SRCS += lookup_nisplus.c
  MODS += lookup_nisplus.so
endif

ifeq ($(YPCLNT), 1)
  SRCS += lookup_yp.c
  MODS += lookup_yp.so
endif

ifeq ($(LDAP), 1)
  SRCS += lookup_ldap.c
  MODS += lookup_ldap.so
  LDAP_FLAGS += $(XML_CFLAGS) -DLDAP_THREAD_SAFE
  LIBLDAP += $(XML_LIBS)
  ifeq ($(SASL), 1)
    SASL_OBJ = cyrus-sasl.o cyrus-sasl-extern.o
    LDAP_FLAGS += $(SASL_FLAGS) $(KRB5_FLAGS)
    LIBLDAP += $(LIBSASL) $(KRB5_LIBS)
  endif
endif

ifeq ($(SSSD), 1)
  CFLAGS += -DSSS_LIB_DIR=\"$(ssslibdir)\"
  SRCS += lookup_sss.c
  MODS += lookup_sss.so
endif

ifeq ($(STATIC), 1)
CFLAGS += -I../include -I../lib -fPIE -D_GNU_SOURCE
else
CFLAGS += -I../include -I../lib -fPIC -D_GNU_SOURCE
endif
CFLAGS += -DAUTOFS_LIB_DIR=\"$(autofslibdir)\"
CFLAGS += -DAUTOFS_MAP_DIR=\"$(autofsmapdir)\"

ifeq ($(STATIC), 1)
# For static builds, build object files instead of shared libraries
OBJS := $(SRCS:.c=.o)
all: $(OBJS)
else
all: $(MODS)
endif

clean:
	rm -f *.o *.s *.so *~ *.output $(YACCSRC)

# mount_smbfs.so is an obsolete module which must be removed
install: all
	install -d -m 755 $(INSTALLROOT)$(autofslibdir)
ifeq ($(STATIC), 1)
	@echo "Static build - no modules to install"
else
	install -c $(MODS) -m 755 $(INSTALLROOT)$(autofslibdir)
	-rm -f $(INSTALLROOT)$(autofslibdir)/mount_smbfs.so
	ln -fs lookup_file.so $(INSTALLROOT)$(autofslibdir)/lookup_files.so
ifeq ($(YPCLNT), 1)
	ln -fs lookup_yp.so $(INSTALLROOT)$(autofslibdir)/lookup_nis.so
endif
ifeq ($(LDAP), 1)
	ln -fs lookup_ldap.so $(INSTALLROOT)$(autofslibdir)/lookup_ldaps.so
endif
	ln -fs mount_nfs.so $(INSTALLROOT)$(autofslibdir)/mount_nfs4.so
endif
ifeq ($(EXT2FS), 1)
 ifeq ($(EXT3FS), 1)
	ln -fs mount_ext2.so $(INSTALLROOT)$(autofslibdir)/mount_ext3.so
 endif
 ifeq ($(EXT4FS), 1)
	ln -fs mount_ext2.so $(INSTALLROOT)$(autofslibdir)/mount_ext4.so
 endif
else ifeq ($(EXT3FS), 1)
	mv $(INSTALLROOT)$(autofslibdir)/mount_ext2.so $(INSTALLROOT)$(autofslibdir)/mount_ext3.so
 ifeq ($(EXT4FS), 1)
	ln -fs mount_ext3.so $(INSTALLROOT)$(autofslibdir)/mount_ext4.so
 endif
else ifeq ($(EXT4FS), 1)
	mv $(INSTALLROOT)$(autofslibdir)/mount_ext2.so $(INSTALLROOT)$(autofslibdir)/mount_ext4.so
endif

amd_tok.c: amd_tok.l
	$(LEX) -o$@ -Pamd_ $?

amd_tok.o: amd_tok.c amd_parse.tab.h

amd_parse.tab.c amd_parse.tab.h: amd_parse.y
	$(YACC) -v -d -p amd_ -b amd_parse $?

amd_parse.tab.o: amd_parse.tab.c amd_parse.tab.h

parse_amd.so: parse_amd.c amd_parse.tab.o amd_tok.o
	$(CC) $(SOLDFLAGS) $(CFLAGS) -o parse_amd.so \
		parse_amd.c amd_parse.tab.o amd_tok.o $(LDFLAGS) $(LIBS) $(AUTOFS_LIB_LINK)
	$(STRIP) parse_amd.so

#
# Ad hoc compilation rules for modules which need auxilliary libraries
#
lookup_yp.so: lookup_yp.c
	$(CC) $(SOLDFLAGS) $(CFLAGS) $(NSLCFLAGS) -o lookup_yp.so \
		lookup_yp.c $(LDFLAGS) $(LIBS) $(NSLLIB) $(AUTOFS_LIB_LINK)
	$(STRIP) lookup_yp.so

lookup_nisplus.so: lookup_nisplus.c
	$(CC) $(SOLDFLAGS) $(CFLAGS) $(NSLCFLAGS) -o lookup_nisplus.so \
		lookup_nisplus.c $(LDFLAGS) $(LIBS) $(NSLLIB) $(AUTOFS_LIB_LINK)
	$(STRIP) lookup_nisplus.so

lookup_hesiod.so: lookup_hesiod.c
	$(CC) $(SOLDFLAGS) $(CFLAGS) $(HESIOD_FLAGS) -o lookup_hesiod.so \
		lookup_hesiod.c $(LDFLAGS) $(LIBHESIOD) $(LIBRESOLV) $(LIBS) $(AUTOFS_LIB_LINK)
	$(STRIP) lookup_hesiod.so

cyrus-sasl.o: cyrus-sasl.c
	$(CC) $(CFLAGS) $(LDAP_FLAGS) -c $<

cyrus-sasl-extern.o: cyrus-sasl-extern.c
	$(CC) $(CFLAGS) $(LDAP_FLAGS) -c $<

lookup_ldap.so: lookup_ldap.c dclist.o base64.o $(SASL_OBJ)
	$(CC) $(SOLDFLAGS) $(CFLAGS) $(LDAP_FLAGS) -o lookup_ldap.so \
		lookup_ldap.c dclist.o base64.o $(SASL_OBJ) \
		$(LDFLAGS) $(LIBLDAP) $(LIBRESOLV) $(LIBS) $(AUTOFS_LIB_LINK)
	$(STRIP) lookup_ldap.so

mount_nfs.so: mount_nfs.c replicated.o
	$(CC) $(SOLDFLAGS) $(CFLAGS) -o mount_nfs.so \
		mount_nfs.c replicated.o $(LDFLAGS) $(LIBS) $(AUTOFS_LIB_LINK)
	$(STRIP) mount_nfs.so

