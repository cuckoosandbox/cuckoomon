CC = gcc
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared

HOOKS = hook_file.c hook_reg.c hook_window.c hook_sync.c hook_process.c

default: cuckoomon.dll

cuckoomon.dll: cuckoomon.c hooking.c log.c $(HOOKS)
	$(CC) $(CFLAGS) $(DLL) -o $@ $^
