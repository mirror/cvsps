CC=gcc
CFLAGS=-O2 -g -Wall -I..

OBJS=\
	cvsps.o\
	../libcommon/hash.o\
	../libcommon/text_util.o\
	../libcommon/debug.o

all: cvsps

cvsps: $(OBJS)
	gcc -o cvsps $(OBJS)


