
TESTS = test-log.exe test-lde.exe

all: $(TESTS)

%.exe: %.c ../log.c ../hooking.c
	gcc -Wall -std=c99 -o $@ $^
