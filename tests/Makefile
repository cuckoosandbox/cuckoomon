
TESTS = test-log.exe test-lde.exe test-hooking.exe test-apihooks.exe \
	test-ldlib.exe test-del.exe test-lasterr.exe

# please build all the object files using the main Makefile (in the parent
# directory)
DISTORM3 = $(shell find '../distorm3.2-package/src/*.o')
CUCKOO = ../log.o ../hooking.o ../misc.o

all: $(TESTS)

%.exe: %.c $(CUCKOO) $(DISTORM3)
	gcc -Wall -std=c99 -s -I../distorm3.2-package/include -I.. -o $@ $^
