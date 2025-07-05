#
# Main Makefile for the autofs user-space tools
#

-include Makefile.conf
include Makefile.rules

.PHONY: daemon all clean samples install install_samples
.PHONY: mrproper distclean backup

all:	daemon 

SUBDIRS=$(shell echo "lib daemon")

daemon:
	set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i all; done 


clean:
	for i in $(SUBDIRS) samples; do \
		if [ -d $$i ]; then $(MAKE) -C $$i clean; fi; done 	

install:
	set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i install; done 	


mrproper distclean: clean
	find . -noleaf \( -name '*~' -o -name '#*' -o -name '*.orig' -o -name '*.rej' -o -name '*.old' \) -print0 | xargs -0 rm -f
	-rm -f include/config.h Makefile.conf config.* .autofs-*
	echo x > .autofs-`cat .version`
	sed -e "s/(\.autofs-[0-9.]\+)/(.autofs-`cat .version`)/" < configure.ac > configure.ac.tmp
	mv -f configure.ac.tmp configure.ac
	rm -f configure
	$(MAKE) configure

TODAY  := $(shell date +'%Y%m%d')
PKGDIR := $(shell basename `pwd`)
VERSION := $(shell cat .version)

backup: mrproper
	cd .. ; tar zcf - $(PKGDIR) | gzip -9 > autofs-$(VERSION)-bu-$(TODAY).tar.gz 

configure: configure.ac aclocal.m4
	autoconf
	autoheader
	rm -rf config.* *.cache

configure.ac: .version
	-rm -f .autofs-*
	echo x > .autofs-`cat .version`
	sed -e "s/(\.autofs-[0-9.]\+)/(.autofs-`cat .version`)/" < configure.ac > configure.ac.tmp
	mv -f configure.ac.tmp configure.ac

-include Makefile.private


