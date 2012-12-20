VERSION=3.0

CC?=gcc
CFLAGS?=-g -O2 -Wall 
CFLAGS+=-I. -DVERSION=\"$(VERSION)\"
prefix?=/usr/local
OBJS=\
	cbtcommon/debug.o\
	cbtcommon/hash.o\
	cbtcommon/text_util.o\
	cbtcommon/sio.o\
	cbtcommon/tcpsocket.o\
	cvsps.o\
	cache.o\
	util.o\
	stats.o\
	cap.o\
	cvs_direct.o\
	list_sort.o

all: cvsps 

cvsps: $(OBJS)
	$(CC) -o cvsps $(OBJS) -lz

check:
	@(cd test >/dev/null; make --quiet)

install:
	[ -d $(prefix)/bin ] || mkdir -p $(prefix)/bin
	[ -d $(prefix)/share/man/man1 ] || mkdir -p $(prefix)/share/man/man1
	install cvsps $(prefix)/bin
	install -m 644 cvsps.1 $(prefix)/share/man/man1

clean:
	rm -f cvsps *.o cbtcommon/*.o core cvsps.spec

cvsps.spec: cvsps.spec.dist
	echo "Version: $(VERSION)" >cvsps.spec

SOURCES = Makefile *.[ch] cbtcommon/*.[ch] merge_utils.sh
DOCS = README COPYING NEWS cvsps.1 TODO
ALL =  $(SOURCES) $(DOCS) control
cvsps-$(VERSION).tar.gz: $(ALL)
	tar --transform='s:^:cvsps-$(VERSION)/:' --show-transformed-names -cvzf cvsps-$(VERSION).tar.gz $(ALL)

dist: cvsps-$(VERSION).tar.gz

release: cvsps-$(VERSION).tar.gz
	shipper -u -m -t; make clean

.PHONY: install clean version dist check
