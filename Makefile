CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra
LDFLAGS=-lcrypto

.PHONY: all
all: nyufile

nyush: nyufile.o

nyush.o: nyufile.c

.PHONY: clean
clean:
	rm -f *.o nyufile
	