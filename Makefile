VERSION=3.11

CC?=gcc
CFLAGS?=-g -O2 -Wall 
CPPFLAGS+=-I. -DVERSION=\"$(VERSION)\"
LDLIBS+=-lz # += to allow solaris and friends add their libs like -lsocket
INSTALL = install
prefix?=/usr/local
target=$(DESTDIR)$(prefix)

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
	$(CC) -o cvsps $(OBJS) $(LDFLAGS) $(LDLIBS)

check:
	@(cd test >/dev/null; make --quiet)

cppcheck:
	cppcheck --template gcc --enable=all --suppress=unusedStructMember *.[ch]

COMMON_PYLINT = --rcfile=/dev/null --reports=n --include-ids=y
PYLINTOPTS1 = $(COMMON_PYLINT) --disable="C0103,C0111,C0301,W0621,R0201,E1103"
pylint:
	@pylint --output-format=parseable $(PYLINTOPTS1) git-cvsimport.py

.SUFFIXES: .html .asc .txt .1

# Requires asciidoc
.asc.1:
	a2x --doctype manpage --format manpage $*.asc
.asc.html:
	a2x --doctype manpage --format xhtml $*.asc
.txt.1:
	a2x --doctype manpage --format manpage $*.txt
.txt.html:
	a2x --doctype manpage --format xhtml $*.txt

install: cvsps.1 all
	$(INSTALL) -d "$(target)/bin"
	$(INSTALL) -d "$(target)/share/man/man1"
	$(INSTALL) cvsps "$(target)/bin"
	$(INSTALL) -m 644 cvsps.1 "$(target)/share/man/man1"

tags: *.c *.h
	ctags *.c *.h

clean:
	rm -f cvsps *.o core tags cvsps.1 cvsps.html docbook-xsl.css

SOURCES = Makefile *.[ch] merge_utils.sh
DOCS = README COPYING NEWS cvsps.asc TODO
ALL =  $(SOURCES) $(DOCS) control
cvsps-$(VERSION).tar.gz: $(ALL)
	tar --transform='s:^:cvsps-$(VERSION)/:' --show-transformed-names -czf cvsps-$(VERSION).tar.gz $(ALL)

dist: cvsps-$(VERSION).tar.gz

release: cvsps-$(VERSION).tar.gz cvsps.html
	rm -f docbook-xsl.css git-cvsimport.html
	shipper version=$(VERSION) | sh -e -x

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

