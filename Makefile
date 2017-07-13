

CC = gcc
CFLAGS =

all:
	$(CC) $(CFLAGS) recv.c
	$(CC) $(CFLAGS) send.c


