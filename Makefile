MAKEFLAGS = -j8
CC = i586-mingw32msvc-cc
CFLAGS = -Wall -std=c99 -s -O2
DLL = -shared
BSONDIR = /opt/mongo-c-driver/src
DIRS = -Idistorm3.2-package/include -I$(BSONDIR)
LIBS = -lws2_32 -lshlwapi
OBJDIR = objects

DISTORM3 = $(wildcard distorm3.2-package/src/*.c)
DISTORM3OBJ = $(DISTORM3:.c=.o)

CUCKOOSRC = $(wildcard *.c)
CUCKOOOBJ = $(CUCKOOSRC:%.c=$(OBJDIR)/%.o)

LOGTBLSRC = logtbl.c
LOGTBLOBJ = $(LOGTBLSRC:%.c=$(OBJDIR)/%.o)

BSONSRC = $(BSONDIR)/bson.c $(BSONDIR)/encoding.c $(BSONDIR)/numbers.c
BSONOBJ = $(OBJDIR)/bson/bson_bson.o $(OBJDIR)/bson/bson_encoding.o $(OBJDIR)/bson/bson_numbers.o

default: $(OBJDIR) $(LOGTBLSRC) cuckoomon.dll

$(OBJDIR):
	mkdir $@ $@/bson

$(LOGTBLSRC): netlog.py
	python netlog.py c-header $@

$(OBJDIR)/bson/bson_%.o: $(BSONDIR)/%.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

cuckoomon.dll: $(CUCKOOOBJ) $(DISTORM3OBJ) $(LOGTBLOBJ) $(BSONOBJ)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^ $(LIBS)

clean:
	rm $(CUCKOOOBJ) $(DISTORM3OBJ) $(LOGTBLSRC) cuckoomon.dll
