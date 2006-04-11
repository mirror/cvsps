VERSION=3.1

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
	util.o\
	stats.o\
	cap.o\
	cvs_direct.o\
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

clean:
	rm -f cvsps *.o cbtcommon/*.o core cvsps.spec cvsps.1 cvsps.html

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

cap.o: ./cbtcommon/debug.h ./cbtcommon/inline.h ./cbtcommon/text_util.h cap.h
cap.o: cvs_direct.h
cvs_direct.o: ./cbtcommon/debug.h ./cbtcommon/inline.h
cvs_direct.o: ./cbtcommon/text_util.h ./cbtcommon/tcpsocket.h
cvs_direct.o: ./cbtcommon/sio.h cvs_direct.h util.h
cvsps.o: ./cbtcommon/hash.h ./cbtcommon/list.h ./cbtcommon/inline.h
cvsps.o: ./cbtcommon/list.h ./cbtcommon/text_util.h ./cbtcommon/debug.h
cvsps.o: cvsps_types.h cvsps.h util.h stats.h cap.h cvs_direct.h list_sort.h
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
