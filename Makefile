include /cobite/share/libversions/Makefile.include-1

#
# use if trying to debug inline functions
#
#CFLAGS+=-fno-inline -fno-default-inline 
#

OBJS=cvsps.o
LIBS=-lcbtcommon
CBTCOMMON_DIST=../libcbtcommon

all: cvsps

cvsps: $(OBJS)
	gcc -Wl,-rpath,/cobite/lib $(LDFLAGS) -o cvsps $(OBJS) $(LIBS)

clean: this_clean

install:
	install cvsps $(CBT_DIR)/bin/

this_clean:
	rm -f *.o cvsps core

dist:
	rm -fr dist/
	mkdir dist/
	mkdir dist/cbtcommon
	cp Makefile.dist dist/Makefile
	cp cvsps.c dist/
	cp README dist/
	cp COPYING dist/
	echo "$(CBTCOMMON_DIST) for dist files"
	cp $(CBTCOMMON_DIST)/list.h dist/cbtcommon/
	cp $(CBTCOMMON_DIST)/hash.h dist/cbtcommon/
	cp $(CBTCOMMON_DIST)/text_util.h dist/cbtcommon/
	cp $(CBTCOMMON_DIST)/debug.h dist/cbtcommon/
	cp $(CBTCOMMON_DIST)/rcsid.h dist/cbtcommon/
	cp $(CBTCOMMON_DIST)/inline.h dist/cbtcommon/
	cp $(CBTCOMMON_DIST)/debug.c dist/cbtcommon/
	cp $(CBTCOMMON_DIST)/hash.c dist/cbtcommon/
	cp $(CBTCOMMON_DIST)/text_util.c dist/cbtcommon/


.PHONY: clean this_clean all dist
