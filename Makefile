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

LOGTBLSRC = logtbl.c
LOGTBLOBJ = $(LOGTBLSRC:%.c=$(OBJDIR)/%.o)

default: $(OBJDIR) $(LOGTBLSRC) cuckoomon.dll

$(OBJDIR):
	mkdir $@

$(LOGTBLSRC): netlog.py
	python netlog.py c-header $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

cuckoomon.dll: $(CUCKOOOBJ) $(DISTORM3OBJ) $(LOGTBLOBJ)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^ $(LIBS)

clean:
	rm $(CUCKOOOBJ) $(DISTORM3OBJ) $(LOGTBLSRC) cuckoomon.dll
