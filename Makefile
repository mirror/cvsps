VERSION=3.2

CC?=gcc
CFLAGS?=-g -O2 -Wall 
CPPFLAGS+=-I. -DVERSION=\"$(VERSION)\"
prefix?=/usr/local
OBJS=\
	cbtcommon/debug.o\
	cbtcommon/hash.o\
	cbtcommon/text_util.o\
	cbtcommon/sio.o\
	cbtcommon/tcpsocket.o\
	cvsps.o\
	util.o\
	stats.o\
	cvsclient.o\
	list_sort.o

all: cvsps 

deps:
	makedepend -Y -I. *.c cbtcommon/*.c

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

tags: *.c *.h cbtcommon/*.c cbtcommon/*.h
	ctags *.c *.h cbtcommon/*.c cbtcommon/*.h

clean:
	rm -f cvsps *.o cbtcommon/*.o core tags cvsps.spec cvsps.1 cvsps.html

cvsps.spec: cvsps.spec.dist
	echo "Version: $(VERSION)" >cvsps.spec

SOURCES = Makefile *.[ch] cbtcommon/*.[ch] merge_utils.sh
DOCS = README COPYING NEWS cvsps.asc TODO
ALL =  $(SOURCES) $(DOCS) control
cvsps-$(VERSION).tar.gz: $(ALL)
	tar --transform='s:^:cvsps-$(VERSION)/:' --show-transformed-names -cvzf cvsps-$(VERSION).tar.gz $(ALL)

dist: cvsps-$(VERSION).tar.gz

release: cvsps-$(VERSION).tar.gz cvsps.html
	shipper -u -m -t; make clean

.PHONY: install clean version dist check
# DO NOT DELETE

cvsclient.o: ./cbtcommon/debug.h ./cbtcommon/inline.h
cvsclient.o: ./cbtcommon/text_util.h ./cbtcommon/tcpsocket.h
cvsclient.o: ./cbtcommon/sio.h cvsclient.h util.h
cvsps.o: ./cbtcommon/hash.h ./cbtcommon/list.h ./cbtcommon/inline.h
cvsps.o: ./cbtcommon/list.h ./cbtcommon/text_util.h ./cbtcommon/debug.h
cvsps.o: cvsps_types.h cvsps.h util.h stats.h cvsclient.h list_sort.h
list_sort.o: list_sort.h ./cbtcommon/list.h
stats.o: ./cbtcommon/hash.h ./cbtcommon/list.h ./cbtcommon/inline.h
stats.o: cvsps_types.h cvsps.h
util.o: ./cbtcommon/debug.h ./cbtcommon/inline.h util.h
cbtcommon/debug.o: cbtcommon/debug.h ./cbtcommon/inline.h
cbtcommon/hash.o: cbtcommon/debug.h ./cbtcommon/inline.h cbtcommon/hash.h
cbtcommon/hash.o: ./cbtcommon/list.h
cbtcommon/sio.o: cbtcommon/sio.h
cbtcommon/tcpsocket.o: cbtcommon/tcpsocket.h cbtcommon/debug.h
cbtcommon/tcpsocket.o: ./cbtcommon/inline.h
cbtcommon/text_util.o: cbtcommon/text_util.h
