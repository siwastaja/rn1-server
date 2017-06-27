CC = gcc
LD = gcc

CFLAGS = -Wall -Winline -std=c99
LDFLAGS = 

DEPS = rn1server.h
OBJ = rn1server.o

all: rn1server

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

rn1server: $(OBJ)
	$(LD) $(LDFLAGS) -o rn1server $^ -lm

e:
	gedit --new-window rn1server.c rn1server.h &
