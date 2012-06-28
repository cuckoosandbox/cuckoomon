
TESTS = test-log.exe

all: $(TESTS)

%.exe: %.c ../log.c
	gcc -Wall -std=c99 -o $@ $^
