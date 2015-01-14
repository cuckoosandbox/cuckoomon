MAKEFLAGS = -j8
CFLAGS = -Wall -std=c99 -s -O2 
LIBS = -ldnsapi -lws2_32 -lwininet -lshlwapi 
CAPSTONELIB = ../../capstone/capstone.lib

ifneq ($(OS),Windows_NT)
	CC = i686-w64-mingw32-gcc
else
	CC = gcc
endif

TESTS = $(wildcard *.c)
TESTSEXE = $(TESTS:.c=.exe)

# please build all the object files using the main Makefile (in the parent
# directory)
CUCKOOOBJ := $(wildcard ../../objects/*.o)
CUCKOOOBJ += $(wildcard ../../objects/bson/*.o)
CUCKOOOBJ += $(wildcard ../../capstone/*.o)

all: $(TESTSEXE)

%.exe: %.c $(CUCKOOOBJ) $(CAPSTONELIB)
	$(CC) $(CFLAGS) -I../.. -I../../capstone -I../../capstone/arch/X86/ -o $@ $^ $(LIBS)

clean:
	rm -f $(TESTSEXE)
