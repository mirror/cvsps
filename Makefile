CC=gcc
CFLAGS=-O2 -g -Wall -I..

OBJS=\
	genps.o\
	../libcommon/hash.o\
	../libcommon/text_util.o\
	../libcommon/debug.o

all: genps

genps: $(OBJS)
	gcc -o genps $(OBJS)


