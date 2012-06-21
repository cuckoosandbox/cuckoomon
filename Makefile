CC = gcc
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared

default: cuckoomon.dll

cuckoomon.dll: cuckoomon.c hook_file.c
	$(CC) $(CFLAGS) $(DLL) -o $@ $^
