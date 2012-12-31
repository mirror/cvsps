VERSION=3.3

CC?=gcc
CFLAGS?=-g -O2 -Wall 
CPPFLAGS+=-I. -DVERSION=\"$(VERSION)\"
prefix?=/usr/local
OBJS= debug.o \
	hash.o \
	sio.o \
	tcpsocket.o \
	cvsps.o \
	util.o \
	stats.o \
	cvsclient.o \
	list_sort.o

all: cvsps 

deps:
	makedepend -Y -I. *.c

cvsps: $(OBJS)
	$(CC) -o cvsps $(OBJS) -lz

check:
	@(cd test >/dev/null; make --quiet)

cppcheck:
	cppcheck --template gcc --enable=all --suppress=unusedStructMember *.[ch]

# Requires asciidoc
cvsps.1: cvsps.asc
	a2x --doctype manpage --format manpage cvsps.asc
cvsps.html: cvsps.asc
	a2x --doctype manpage --format xhtml cvsps.asc

install: cvsps.1
	[ -d $(prefix)/bin ] || mkdir -p $(prefix)/bin
	[ -d $(prefix)/share/man/man1 ] || mkdir -p $(prefix)/share/man/man1
	install cvsps $(prefix)/bin
	install -m 644 cvsps.1 $(prefix)/share/man/man1

tags: *.c *.h
	ctags *.c *.h

clean:
	rm -f cvsps *.o core tags cvsps.1 cvsps.html docbook-xsl.css

SOURCES = Makefile *.[ch] merge_utils.sh
DOCS = README COPYING NEWS cvsps.asc TODO
ALL =  $(SOURCES) $(DOCS) control
cvsps-$(VERSION).tar.gz: $(ALL)
	tar --transform='s:^:cvsps-$(VERSION)/:' --show-transformed-names -cvzf cvsps-$(VERSION).tar.gz $(ALL)

dist: cvsps-$(VERSION).tar.gz

release: cvsps-$(VERSION).tar.gz cvsps.html
	shipper -u -m -t; make clean

.PHONY: install clean version dist check
# DO NOT DELETE

cvsclient.o: debug.h inline.h
cvsclient.o: tcpsocket.h
cvsclient.o: sio.h cvsclient.h util.h
cvsps.o: hash.h list.h inline.h
cvsps.o: list.h debug.h
cvsps.o: cvsps_types.h cvsps.h util.h stats.h cvsclient.h list_sort.h
list_sort.o: list_sort.h list.h
stats.o: hash.h list.h inline.h
stats.o: cvsps_types.h cvsps.h
util.o: debug.h inline.h util.h
debug.o: debug.h inline.h
hash.o: debug.h inline.h hash.h
hash.o: list.h
sio.o: sio.h
tcpsocket.o: tcpsocket.h debug.h
tcpsocket.o: inline.h

