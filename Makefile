# use if trying to debug inline functions
#
#CFLAGS=-fno-inline -fno-default-inline -g -Wall -I..
#
# otherwise...
CFLAGS=-O2 -g -Wall -I..
#

CC=gcc
OBJS=\
	cvsps.o\
	../libcommon/hash.o\
	../libcommon/text_util.o\
	../libcommon/debug.o

all: cvsps

cvsps: $(OBJS)
	gcc -o cvsps $(OBJS)

clean:
	rm -f *.o cvsps core


.PHONY: clean
