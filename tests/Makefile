MAKEFLAGS = -j8

TESTS = $(wildcard *.c)
TESTSEXE = $(TESTS:.c=.exe)

# please build all the object files using the main Makefile (in the parent
# directory)
DISTORM3 = $(wildcard ../distorm3.2-package/src/*.c)
DISTORM3OBJ = $(DISTORM3:.c=.o)
CUCKOOOBJ = $(wildcard ../objects/*.o)

all: $(TESTSEXE)

%.exe: %.c $(CUCKOOOBJ) $(DISTORM3OBJ)
	gcc -Wall -std=c99 -s -I../distorm3.2-package/include -I.. -o $@ $^ \
		-ldnsapi -lws2_32 -lwininet -lshlwapi

clean:
	rm $(TESTSEXE)
