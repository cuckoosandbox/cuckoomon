CC = gcc
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared

HOOKS = hook_file.c hook_reg.c hook_window.c

default: cuckoomon.dll

cuckoomon.dll: cuckoomon.c hooking.c log.c $(HOOKS)
	$(CC) $(CFLAGS) $(DLL) -o $@ $^
