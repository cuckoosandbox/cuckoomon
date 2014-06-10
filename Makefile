MAKEFLAGS = -j8
CFLAGS = -Wall -std=c99 -s -O2 -Wno-strict-aliasing
DLL = -shared
DIRS = -Ibson -Icapstone
LIBS = -lws2_32 -lshlwapi
OBJDIR = objects

# Passes DBG=1 on as -DCUCKOODBG=1
ifdef DBG
	CFLAGS += -DCUCKOODBG=$(DBG)
endif

ifneq ($(OS),Windows_NT)
	CC = i586-mingw32msvc-cc
	# CC = i686-w64-mingw32-gcc
else
	CC = gcc
endif

CUCKOOSRC = $(wildcard *.c)
CUCKOOOBJ = $(CUCKOOSRC:%.c=$(OBJDIR)/%.o)

CAPSTONELIB = capstone/capstone.lib

BSONSRC = bson/bson.c bson/encoding.c bson/numbers.c
BSONOBJ = $(OBJDIR)/bson/bson.o $(OBJDIR)/bson/encoding.o $(OBJDIR)/bson/numbers.o

default: $(CAPSTONELIB) $(OBJDIR) cuckoomon.dll

$(OBJDIR):
	mkdir $@ $@/bson $@/capstone

$(OBJDIR)/bson/%.o: bson/%.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(DIRS) -c $^ -o $@

$(CAPSTONELIB):
	git submodule update --init && \
	cp capstone-config.mk capstone/config.mk && \
	cd capstone && ./make.sh cross-win32

cuckoomon.dll: $(CUCKOOOBJ) $(BSONOBJ) $(CAPSTONELIB)
	$(CC) $(CFLAGS) $(DLL) $(DIRS) -o $@ $^ $(LIBS)

clean:
	rm -rf $(OBJDIR) cuckoomon.dll
