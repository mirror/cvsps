include /cobite/share/libversions/Makefile.include-1

#
# use if trying to debug inline functions
#
#CFLAGS+=-fno-inline -fno-default-inline 
#

OBJS=cvsps.o
LIBS=-lcbtcommon

all: cvsps

cvsps: $(OBJS)
	gcc -Wl,-rpath,/cobite/lib $(LDFLAGS) -o cvsps $(OBJS) $(LIBS)

clean: this_clean

install:
	install cvsps $(CBT_DIR)/bin/

this_clean:
	rm -f *.o cvsps core

.PHONY: clean this_clean all
