MAJOR=2
MINOR=2b1

CC?=gcc
CFLAGS?=-g -O2 -Wall 
CFLAGS+=-I. -DVERSION=\"$(MAJOR).$(MINOR)\"
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

install:
	[ -d $(prefix)/bin ] || mkdir -p $(prefix)/bin
	[ -d $(prefix)/share/man/man1 ] || mkdir -p $(prefix)/share/man/man1
	install cvsps $(prefix)/bin
	install -m 644 cvsps.1 $(prefix)/share/man/man1

clean:
	rm -f cvsps *.o cbtcommon/*.o core cvsps.spec

cvsps.spec: cvsps.spec.dist
	echo "Version: $(MAJOR).$(MINOR)" >cvsps.spec

SOURCES = Makefile *.[ch] cbtcommon/*.[ch] merge_utils.sh
DOCS = README COPYING CHANGELOG cvsps.1 TODO
ALL =  $(SOURCES) $(DOCS)
cvsps-$(MAJOR).$(MINOR).tar.gz: $(ALL)
	tar --transform='s:^:cvsps-$(MAJOR).$(MINOR)/:' --show-transformed-names -cvzf cvsps-$(MAJOR).$(MINOR).tar.gz $(ALL)

dist: cvsps-$(MAJOR).$(MINOR).tar.gz

.PHONY: install clean version dist
