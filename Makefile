CFLAGS=-g -O3 -Wall
PROGRAM=statsd-local-repeater

all: statsd-local-repeater

statsd-local-repeater: main.o
	$(CC) -o statsd-local-repeater main.o -lpcap

.PHONY: clean
clean:
	rm main.o $(PROGRAM)
