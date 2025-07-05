#
# Makefile for autofs utility library
#

-include ../Makefile.conf
include ../Makefile.rules

ifeq ($(STATIC), 1)
# For static builds, exclude RPC-dependent modules
SRCS = cache.c cat_path.c mounts.c log.c nsswitch.c \
	nss_tok.c nss_parse.tab.c args.c alarm.c macros.c defaults.c \
	parse_subs.c dev-ioctl-lib.c
OBJS = cache.o cat_path.o mounts.o log.o nsswitch.o \
	nss_tok.o nss_parse.tab.o args.o alarm.o macros.o defaults.o \
	parse_subs.o dev-ioctl-lib.o
else
SRCS = cache.c cat_path.c rpc_subs.c mounts.c log.c nsswitch.c \
	nss_tok.c nss_parse.tab.c args.c alarm.c macros.c defaults.c \
	parse_subs.c dev-ioctl-lib.c
OBJS = cache.o cat_path.o rpc_subs.o mounts.o log.o nsswitch.o \
	nss_tok.o nss_parse.tab.o args.o alarm.o macros.o defaults.o \
	parse_subs.o dev-ioctl-lib.o
endif

YACCSRC = nss_tok.c nss_parse.tab.c nss_parse.tab.h

LIB = libautofs.so
STATIC_LIB = libautofs.a

ifeq ($(STATIC), 1)
CFLAGS += -I../include -fPIE -D_GNU_SOURCE
else
CFLAGS += -I../include -fPIC -D_GNU_SOURCE
endif
CFLAGS += -DAUTOFS_MAP_DIR=\"$(autofsmapdir)\"
CFLAGS += -DAUTOFS_CONF_DIR=\"$(autofsconfdir)\"

ifeq ($(LDAP), 1)
  CFLAGS += $(XML_CFLAGS) $(XML_LIBS)
endif

.PHONY: all install clean

ifeq ($(STATIC), 1)
all: $(STATIC_LIB)

$(STATIC_LIB): $(OBJS)
	$(AR) rcs $@ $^
	$(RANLIB) $@
else
all: $(LIB)

$(LIB): $(OBJS)
	$(CC) $(SOLDFLAGS) $(CFLAGS) -o $*.so $^ $(LDFLAGS) $(LIBS)
	$(STRIP) $*.so
endif

nss_tok.c: nss_tok.l
	$(LEX) -o$@ -Pnss_ $?

nss_parse.tab.c nss_parse.tab.h: nss_parse.y
	$(YACC) -v -d -p nss_ -b nss_parse $?

nss_tok.o: nss_tok.c nss_parse.tab.h

nss_parse.tab.o: nss_parse.tab.c nss_parse.tab.h

install: all
	install -d -m 755 $(INSTALLROOT)$(autofslibdir)
ifeq ($(STATIC), 1)
	install -c $(STATIC_LIB) -m 644 $(INSTALLROOT)$(sharedlibdir)
else
	install -c $(LIB) -m 755 $(INSTALLROOT)$(sharedlibdir)
endif

clean:
	rm -f $(LIB) $(STATIC_LIB) $(RPCS) $(OBJS) $(YACCSRC) *.output *~

