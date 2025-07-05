#
# Makefile for autofs
#

-include ../Makefile.conf
include ../Makefile.rules

SRCS = automount.c indirect.c direct.c spawn.c module.c mount.c \
	master.c master_tok.l master_parse.y lookup.c state.c flag.c
OBJS = automount.o indirect.o direct.o spawn.o module.o mount.o \
	master.o master_tok.o master_parse.tab.o lookup.o state.o \
	flag.o

ifeq ($(STATIC), 1)
OBJS += ../modules/lookup_file.o ../modules/lookup_program.o ../modules/parse_sun.o ../modules/mount_generic.o
endif

YACCSRC = master_tok.c master_parse.tab.c master_parse.tab.h

version := $(shell cat ../.version)

ifeq ($(STATIC), 1)
CFLAGS += $(DAEMON_CFLAGS) -D_GNU_SOURCE -I../include -DENABLE_STATIC_BUILD
LDFLAGS +=
LIBS += -lpthread
else
CFLAGS += -rdynamic $(DAEMON_CFLAGS) -D_GNU_SOURCE -I../include
LDFLAGS += -rdynamic
LIBS += -ldl -lpthread
endif

CFLAGS += -DAUTOFS_LIB_DIR=\"$(autofslibdir)\"
CFLAGS += -DAUTOFS_MAP_DIR=\"$(autofsmapdir)\"
CFLAGS += -DAUTOFS_CONF_DIR=\"$(autofsconfdir)\"
CFLAGS += -DAUTOFS_FIFO_DIR=\"$(autofsfifodir)\"
CFLAGS += -DAUTOFS_FLAG_DIR=\"$(autofsflagdir)\"
CFLAGS += -DVERSION_STRING=\"$(version)\"

ifeq ($(STATIC), 1)
# For static build, disable systemd and LDAP to reduce dependencies
else
ifeq ($(SYSTEMD), 1)
    CFLAGS += -DWITH_SYSTEMD
    LIBS += $(LIBSYSTEMD)
endif

ifeq ($(LDAP), 1)
    CFLAGS += $(XML_CFLAGS)
    LIBS += $(XML_LIBS)
endif
endif

all: automount

ifeq ($(STATIC), 1)
automount: $(OBJS) ../lib/libautofs.a
	$(CC) $(DAEMON_LDFLAGS) -o automount $(OBJS) $(LDFLAGS) $(LIBS) ../lib/libautofs.a
	$(STRIP) automount
else
automount: $(OBJS) $(AUTOFS_LIB)
	$(CC) $(DAEMON_LDFLAGS) -o automount $(OBJS) $(LDFLAGS) $(LIBS) $(AUTOFS_LIB_LINK)
	$(STRIP) automount
endif

master_tok.c: master_tok.l
	$(LEX) -o$@ -Pmaster_ $?

master_parse.tab.c master_parse.tab.h: master_parse.y
	$(YACC) -v -d -p master_ -b master_parse $?

master_tok.o: master_tok.c master_parse.tab.h

master_parse.tab.o: master_parse.tab.c master_parse.tab.h

clean:
	rm -f *.o *.s *~ $(YACCSRC) *.output *~ automount

install: all
	install -d -m 755 $(INSTALLROOT)$(sbindir)
	install -c automount -m 755 $(INSTALLROOT)$(sbindir)


