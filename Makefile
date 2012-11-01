CC = gcc
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared
DIRS = -Idistorm3.2-package/include

DISTORM3 = $(wildcard distorm3.2-package/src/*.c)
DISTORM3OBJ = $(DISTORM3:.c=.o)

HOOKS = $(wildcard hook_*.c)
HOOKSOBJ = $(HOOKS:.c=.o)

CUCKOO = hooking.o log.o special.o pipe.o misc.o cuckoomon.o ignore.o

default: cuckoomon.dll

%.o: %.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

cuckoomon.dll: $(CUCKOO) $(HOOKSOBJ) $(DISTORM3OBJ)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^

clean:
	rm $(CUCKOO) $(HOOKSOBJ) $(DISTORM3OBJ) cuckoomon.dll
