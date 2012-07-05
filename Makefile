CC = gcc
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared
DIRS = -Idistorm3.2-package/include

HOOKS = $(patsubst %.c, %.o, $(shell find 'hook_*.c'))
DISTORM3 = $(patsubst %.c, %.o, $(shell find 'distorm3.2-package/src/*.c'))
CUCKOO = hooking.o log.o special.o

default: cuckoomon.dll

%.o: %.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

cuckoomon.dll: cuckoomon.c $(CUCKOO) $(HOOKS) $(DISTORM3)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^

clean:
	rm $(CUCKOO) $(HOOKS) $(DISTORM3) cuckoomon.dll
