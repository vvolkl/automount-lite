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

YACCSRC = master_tok.c master_parse.tab.c master_parse.tab.h

version := $(shell cat ../.version)

CFLAGS += -rdynamic $(DAEMON_CFLAGS) -D_GNU_SOURCE -I../include
CFLAGS += -DAUTOFS_LIB_DIR=\"$(autofslibdir)\" 
CFLAGS += -DAUTOFS_MAP_DIR=\"$(autofsmapdir)\"
CFLAGS += -DAUTOFS_CONF_DIR=\"$(autofsconfdir)\"
CFLAGS += -DAUTOFS_FIFO_DIR=\"$(autofsfifodir)\"
CFLAGS += -DAUTOFS_FLAG_DIR=\"$(autofsflagdir)\"
CFLAGS += -DVERSION_STRING=\"$(version)\"
LDFLAGS += -rdynamic
LIBS += -ldl -lpthread

ifeq ($(SYSTEMD), 1)
    CFLAGS += -DWITH_SYSTEMD
    LIBS += $(LIBSYSTEMD)
endif

ifeq ($(LDAP), 1)
    CFLAGS += $(XML_CFLAGS)
    LIBS += $(XML_LIBS)
endif

all: automount

automount: $(OBJS) $(AUTOFS_LIB)
	$(CC) $(DAEMON_LDFLAGS) -o automount $(OBJS) $(LDFLAGS) $(LIBS) $(AUTOFS_LIB_LINK)
	$(STRIP) automount

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


