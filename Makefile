CC=gcc
CFLAGS=-fno-inline -fno-default-inline -g -Wall -I..

OBJS=\
	cvsps.o\
	../libcommon/hash.o\
	../libcommon/text_util.o\
	../libcommon/debug.o

all: cvsps

cvsps: $(OBJS)
	gcc -o cvsps $(OBJS)


