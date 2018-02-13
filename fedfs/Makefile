#
# Makefile for mount.fedfs
#

-include ../Makefile.conf
include ../Makefile.rules

SRCS = mount.fedfs.c
HDRS = fedfs-getsrvinfo.h fedfs-gpl-boiler.h fedfs-nls.h

fedfs-getsrvinfo_OBJ = fedfs-getsrvinfo.o

mount_fedfs_OBJ = mount.fedfs.o

version := $(shell cat ../.version)

CFLAGS += -rdynamic $(DAEMON_CFLAGS) -D_GNU_SOURCE -I../include
CFLAGS += -DVERSION_STRING=\"$(version)\"
LDFLAGS += -rdynamic

all: mount.fedfs

mount.fedfs: $(mount_fedfs_OBJ) $(fedfs-getsrvinfo_OBJ) $(HDRS)
	$(CC) -o mount.fedfs \
	       $(mount_fedfs_OBJ) $(fedfs-getsrvinfo_OBJ) \
	       $(LDFLAGS) $(LIBRESOLV) $(LIBS)

clean:
	rm -f *.o *.s *~ mount.fedfs

install: all
	install -d -m 755 $(INSTALLROOT)$(sbindir)
	if ! test -x $(INSTALLROOT)$(sbindir)/mount.fedfs; \
	then \
		install -c mount.fedfs -m 755 $(INSTALLROOT)$(sbindir); \
	fi
