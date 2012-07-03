CC = gcc
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared
DIRS = -Idistorm3.2-package/include

HOOKS = hook_file.c hook_reg.c hook_window.c hook_sync.c hook_process.c \
	hook_thread.c hook_misc.c hook_network.c hook_services.c

DISTORM3 = $(patsubst %.c, %.o, $(shell find 'distorm3.2-package/src/*.c'))

default: $(DISTORM3) cuckoomon.dll

distorm3.2-package/src/%.o: %.c
	$(CC) $(CFLAGS) -c $@ $^

cuckoomon.dll: cuckoomon.c hooking.c log.c special.c $(HOOKS) $(DISTORM3)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^
