#
# Makefile for autofs utility library
#

-include ../Makefile.conf
include ../Makefile.rules

SRCS = cache.c cat_path.c rpc_subs.c mounts.c log.c nsswitch.c \
	nss_tok.c nss_parse.tab.c args.c alarm.c macros.c defaults.c \
	parse_subs.c dev-ioctl-lib.c
RPCS = mount.h mount_clnt.c mount_xdr.c
OBJS = cache.o mount_clnt.o mount_xdr.o cat_path.o rpc_subs.o \
	mounts.o log.o nsswitch.o nss_tok.o nss_parse.tab.o args.o \
	alarm.o macros.o defaults.o parse_subs.o dev-ioctl-lib.o

YACCSRC = nss_tok.c nss_parse.tab.c nss_parse.tab.h

LIB = libautofs.so

CFLAGS += -I../include -fPIC -D_GNU_SOURCE
CFLAGS += -DAUTOFS_MAP_DIR=\"$(autofsmapdir)\"
CFLAGS += -DAUTOFS_CONF_DIR=\"$(autofsconfdir)\"

ifeq ($(LDAP), 1)
  CFLAGS += $(XML_CFLAGS) $(XML_LIBS)
endif

.PHONY: all install clean

all: libautofs.so

libautofs.so: $(OBJS)
	$(CC) $(SOLDFLAGS) $(CFLAGS) -o $*.so $^ $(LDFLAGS) $(LIBS)
	$(STRIP) $*.so

mount.h: mount.x
	$(RPCGEN) -h -o mount.h mount.x

mount_clnt.c: mount.h
	$(RPCGEN) -l -o mount_clnt.c mount.x

mount_clnt.o: mount_clnt.c
	$(CC) $(CFLAGS) -o mount_clnt.o -c mount_clnt.c
	$(STRIP) mount_clnt.o

mount_xdr.c: mount.h
	$(RPCGEN) -c -o mount_xdr.c mount.x

mount_xdr.o: mount_xdr.c
	$(CC) $(CFLAGS) -Wno-unused-variable -o mount_xdr.o -c mount_xdr.c
	$(STRIP) mount_xdr.o

nss_tok.c: nss_tok.l
	$(LEX) -o$@ -Pnss_ $?

nss_parse.tab.c nss_parse.tab.h: nss_parse.y
	$(YACC) -v -d -p nss_ -b nss_parse $?

nss_tok.o: nss_tok.c nss_parse.tab.h

nss_parse.tab.o: nss_parse.tab.c nss_parse.tab.h

rpc_subs.o: mount.h

install: all
	install -d -m 755 $(INSTALLROOT)$(autofslibdir)
	install -c $(LIB) -m 755 $(INSTALLROOT)$(sharedlibdir)

clean:
	rm -f $(LIB) $(RPCS) $(OBJS) $(YACCSRC) *.output *~

