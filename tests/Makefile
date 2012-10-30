
TESTS = test-log.exe test-lde.exe test-hooking.exe test-apihooks.exe \
	test-ldlib.exe test-del.exe test-lasterr.exe test-dns.exe test-dir.exe

# please build all the object files using the main Makefile (in the parent
# directory)
DISTORM3 = $(wildcard ../distorm3.2-package/src/*.c)
DISTORM3OBJ = $(DISTORM3:.c=.o)
CUCKOO = ../log.o ../hooking.o ../misc.o

all: $(TESTS)

%.exe: %.c $(CUCKOO) $(DISTORM3OBJ)
	gcc -Wall -std=c99 -s -I../distorm3.2-package/include -I.. -o $@ $^ \
		-ldnsapi -lws2_32
