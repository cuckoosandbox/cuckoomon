# MAKEFLAGS = -j8
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared
DIRS = -Idistorm3.2-package/include -Ibson
LIBS = -lws2_32 -lshlwapi
OBJDIR = objects

ifneq ($(OS),Windows_NT)
	CC = i586-mingw32msvc-cc
else
	CC = gcc
endif

DISTORM3 = $(wildcard distorm3.2-package/src/*.c)
DISTORM3OBJ = $(DISTORM3:.c=.o)

CUCKOOSRC = $(wildcard *.c)
CUCKOOOBJ = $(CUCKOOSRC:%.c=$(OBJDIR)/%.o)

LOGTBLSRC = logtbl.c
LOGTBLOBJ = $(LOGTBLSRC:%.c=$(OBJDIR)/%.o)

BSONSRC = bson/bson.c bson/encoding.c bson/numbers.c
BSONOBJ = $(OBJDIR)/bson/bson.o $(OBJDIR)/bson/encoding.o $(OBJDIR)/bson/numbers.o

default: $(OBJDIR) $(LOGTBLSRC) cuckoomon.dll

$(OBJDIR):
	mkdir $@ $@/bson

$(LOGTBLSRC): netlog.py
	python netlog.py c-header $@

$(OBJDIR)/bson/%.o: bson/%.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

cuckoomon.dll: $(CUCKOOOBJ) $(DISTORM3OBJ) $(LOGTBLOBJ) $(BSONOBJ)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^ $(LIBS)

clean:
	rm $(CUCKOOOBJ) $(DISTORM3OBJ) $(LOGTBLSRC) cuckoomon.dll
