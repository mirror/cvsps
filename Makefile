DEP_OBJS=cvsps.o cache.o util.o stats.o cap.o cvs_direct.o
CBT_DIR=/cobite
include $(CBT_DIR)/share/libversions/Makefile.include-1

ifeq ($(DEBUG_INLINING), y)
CFLAGS+=-fno-inline -fno-default-inline -O0 -g
endif

OBJS=$(DEP_OBJS)
LIBS=-lcbtcommon
CBTCOMMON_DIST=../libcbtcommon
MAJOR=2
MINOR=0b6
CFLAGS+=-DVERSION=\"$(MAJOR).$(MINOR)_CBT\"


ifeq "$(CONFIG)" "Debug"
RPATH+=$(CBT_DIR)/lib/debug
else
RPATH=$(CBT_DIR)/lib
endif

all: cvsps

cvsps: $(OBJS)
	gcc -Wl,-rpath,$(RPATH) $(LDFLAGS) -o cvsps $(OBJS) $(LIBS)

clean: this_clean

install:
	install cvsps $(CBT_DIR)/bin/

this_clean:
	rm -f *.o *.d cvsps core
	rm -fr dist/ htdocs/

dist:
	rm -fr dist/
	mkdir dist/
	mkdir dist/cbtcommon
	echo MAJOR=$(MAJOR) >dist/Makefile
	echo MINOR=$(MINOR) >>dist/Makefile
	cat Makefile.dist >>dist/Makefile
	echo "Version: $(MAJOR).$(MINOR)" >dist/cvsps.spec
	cat cvsps.spec.dist >>dist/cvsps.spec
	cat copyright.head cvsps.c >dist/cvsps.c
	cat copyright.head cvsps.h >dist/cvsps.h
	cat copyright.head cache.c >dist/cache.c
	cat copyright.head cache.h >dist/cache.h
	cat copyright.head util.c >dist/util.c
	cat copyright.head util.h >dist/util.h
	cat copyright.head cvsps_types.h >dist/cvsps_types.h
	cat copyright.head stats.c >dist/stats.c
	cat copyright.head stats.h >dist/stats.h
	cat copyright.head cap.c >dist/cap.c
	cat copyright.head cap.h >dist/cap.h
	cp README dist/
	cp COPYING dist/
	cp cvsps.1 dist/
	cp CHANGELOG dist/
	cp merge_utils.sh dist/
	@echo "NOTE: Using $(CBTCOMMON_DIST) for dist files"
	cat copyright.head $(CBTCOMMON_DIST)/list.h >dist/cbtcommon/list.h
	cat copyright.head $(CBTCOMMON_DIST)/hash.h >dist/cbtcommon/hash.h
	cat copyright.head $(CBTCOMMON_DIST)/text_util.h >dist/cbtcommon/text_util.h
	cat copyright.head $(CBTCOMMON_DIST)/debug.h >dist/cbtcommon/debug.h
	cat copyright.head $(CBTCOMMON_DIST)/rcsid.h >dist/cbtcommon/rcsid.h
	cat copyright.head $(CBTCOMMON_DIST)/inline.h >dist/cbtcommon/inline.h
	cat copyright.head $(CBTCOMMON_DIST)/debug.c >dist/cbtcommon/debug.c
	cat copyright.head $(CBTCOMMON_DIST)/hash.c >dist/cbtcommon/hash.c
	cat copyright.head $(CBTCOMMON_DIST)/text_util.c >dist/cbtcommon/text_util.c

htdocs: dist
	rm -fr htdocs/
	mkdir htdocs/
	cp README htdocs/
	cp CHANGELOG htdocs/
	cp site/*.html site/*.gif htdocs/
	mv dist cvsps-$(MAJOR).$(MINOR)
	tar cvzf htdocs/cvsps-$(MAJOR).$(MINOR).tar.gz cvsps-$(MAJOR).$(MINOR)
	mv cvsps-$(MAJOR).$(MINOR) dist

.PHONY: clean this_clean all dist htdocs
