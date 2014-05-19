MAKEFLAGS = -j8
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared
DIRS = -Idistorm3.2-package/include -Ibson
LIBS = -lws2_32 -lshlwapi
OBJDIR = objects

# Passes DBG=1 on as -DCUCKOODBG=1
ifdef DBG
	CFLAGS += -DCUCKOODBG=$(DBG)
endif

ifneq ($(OS),Windows_NT)
	CC = i586-mingw32msvc-cc
else
	CC = gcc
endif

DISTORM3 = $(wildcard distorm3.2-package/src/*.c)
DISTORM3OBJ = $(DISTORM3:distorm3.2-package/src/%.c=$(OBJDIR)/distorm3.2/%.o)

CUCKOOSRC = $(wildcard *.c)
CUCKOOOBJ = $(CUCKOOSRC:%.c=$(OBJDIR)/%.o)

LOGTBLSRC = logtbl.c
LOGTBLOBJ = $(LOGTBLSRC:%.c=$(OBJDIR)/%.o)

BSONSRC = bson/bson.c bson/encoding.c bson/numbers.c
BSONOBJ = $(OBJDIR)/bson/bson.o $(OBJDIR)/bson/encoding.o $(OBJDIR)/bson/numbers.o

default: $(OBJDIR) $(LOGTBLSRC) cuckoomon.dll

$(OBJDIR):
	mkdir $@ $@/bson $@/distorm3.2

$(LOGTBLSRC): netlog.py
	python netlog.py c-header $@

$(OBJDIR)/distorm3.2/%.o: distorm3.2-package/src/%.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

$(OBJDIR)/bson/%.o: bson/%.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

cuckoomon.dll: $(CUCKOOOBJ) $(DISTORM3OBJ) $(LOGTBLOBJ) $(BSONOBJ)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^ $(LIBS)

clean:
	rm -rf $(OBJDIR) $(LOGTBLSRC) cuckoomon.dll
