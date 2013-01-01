MAKEFLAGS = -j8
CC = gcc
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared
DIRS = -Idistorm3.2-package/include
LIBS = -lws2_32 -lshlwapi
OBJDIR = objects

DISTORM3 = $(wildcard distorm3.2-package/src/*.c)
DISTORM3OBJ = $(DISTORM3:.c=.o)

CUCKOOSRC = $(wildcard *.c)
CUCKOOOBJ = $(CUCKOOSRC:%.c=$(OBJDIR)/%.o)

default: $(OBJDIR) cuckoomon.dll

$(OBJDIR):
	mkdir $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

cuckoomon.dll: $(CUCKOOOBJ) $(DISTORM3OBJ)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^ $(LIBS)

clean:
	rm $(CUCKOOOBJ) $(DISTORM3OBJ) cuckoomon.dll
