#
# Makefile for mount.fedfs
#

-include ../Makefile.conf
include ../Makefile.rules

SRCS = mount.fedfs.c
HDRS = fedfs-getsrvinfo.h fedfs-gpl-boiler.h fedfs-nls.h \
       fedfs-token.h

fedfs-getsrvinfo_OBJ = fedfs-getsrvinfo.o

mount_fedfs_OBJ = mount.fedfs.o
fedfs-map-nfs4_OBJ = fedfs-map-nfs4.o

version := $(shell cat ../.version)

CFLAGS += -rdynamic $(DAEMON_CFLAGS) -D_GNU_SOURCE -I../include
CFLAGS += -DVERSION_STRING=\"$(version)\"
LDFLAGS += -rdynamic

all: mount.fedfs fedfs-map-nfs4

mount.fedfs: $(mount_fedfs_OBJ) $(fedfs-getsrvinfo_OBJ) $(HDRS)
	$(CC) $(DAEMON_LDFLAGS) -o mount.fedfs \
	       $(mount_fedfs_OBJ) $(fedfs-getsrvinfo_OBJ) \
	       $(LDFLAGS) $(LIBRESOLV) $(LIBS)

fedfs-map-nfs4: $(fedfs-map-nfs4_OBJ) $(fedfs-getsrvinfo_OBJ) $(HDRS)
	$(CC) $(DAEMON_LDFLAGS) -o fedfs-map-nfs4 \
	       $(fedfs-map-nfs4_OBJ) $(fedfs-getsrvinfo_OBJ) \
	       $(LDFLAGS) $(LIBRESOLV) $(LIBS)

clean:
	rm -f *.o *.s *~ mount.fedfs

install: all
	install -d -m 755 $(INSTALLROOT)$(sbindir)
	install -c fedfs-map-nfs4 -m 755 $(INSTALLROOT)$(sbindir); \
	if ! test -x $(INSTALLROOT)$(sbindir)/mount.fedfs; \
	then \
		install -c mount.fedfs -m 755 $(INSTALLROOT)$(sbindir); \
	fi
