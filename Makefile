

CC = gcc
CFLAGS =

all:
	$(CC) $(CFLAGS) recv.c -o recv.out
	$(CC) $(CFLAGS) send.c -o send.out


