/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2013 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <windows.h>
#include "ntapi.h"
#include "ignore.h"
#include "misc.h"
#include "pipe.h"

//
// Protected Processes
//

static unsigned long g_pids[MAX_PROTECTED_PIDS];
static unsigned long g_pid_count;

void add_protected_pid(unsigned long pid)
{
    g_pids[g_pid_count++] = pid;
}

int is_protected_pid(unsigned long pid)
{
    for (unsigned long i = 0; i < g_pid_count; i++) {
        if(pid == g_pids[i]) {
            return 1;
        }
    }
    return 0;
}

//
// Blacklist for Dumping Files
//

#define S(s, f) {L##s, sizeof(s)-1, f}

#define FLAG_NONE           0
#define FLAG_BEGINS_WITH    1

static struct _ignored_file_t {
    const wchar_t   *unicode;
    unsigned int    length;
    unsigned int    flags;
} g_ignored_files[] = {
    S("\\??\\PIPE\\lsarpc", FLAG_NONE),
    S("\\??\\IDE#", FLAG_BEGINS_WITH),
    S("\\??\\STORAGE#", FLAG_BEGINS_WITH),
    S("\\??\\MountPointManager", FLAG_NONE),
    S("\\??\\root#", FLAG_BEGINS_WITH),
    S("\\Device\\", FLAG_BEGINS_WITH),
};

int is_ignored_file_unicode(const wchar_t *fname, int length)
{
    struct _ignored_file_t *f = g_ignored_files;
    for (unsigned int i = 0; i < ARRAYSIZE(g_ignored_files); i++, f++) {
        if(f->flags == FLAG_NONE && length == f->length &&
                !wcsnicmp(fname, f->unicode, length)) {
            return 1;
        }
        else if(f->flags == FLAG_BEGINS_WITH && length >= f->length &&
                !wcsnicmp(fname, f->unicode, f->length)) {
            return 1;
        }
    }
    return 0;
}

int is_ignored_file_objattr(const OBJECT_ATTRIBUTES *obj)
{
    return is_ignored_file_unicode(obj->ObjectName->Buffer,
        obj->ObjectName->Length / sizeof(wchar_t));
}

static wchar_t *g_ignored_processpaths[] = {
    L"C:\\WINDOWS\\system32\\dwwin.exe",
    L"C:\\WINDOWS\\system32\\dumprep.exe",
    L"C:\\WINDOWS\\system32\\drwtsn32.exe",
};

int is_ignored_process()
{
    wchar_t process_path[MAX_PATH];
    GetModuleFileNameW(NULL, process_path, ARRAYSIZE(process_path));

    for (int i = 0; i < ARRAYSIZE(g_ignored_processpaths); i++) {
        if(!wcsicmp(g_ignored_processpaths[i], process_path)) {
            return 1;
        }
    }
    return 0;
}

//
// Whitelist for Return Addresses
//

// for each high 20-bits of an address, there are two bits:
// - is this address ignored
// - is the ignored bit initialized yet?
static unsigned char retaddr[0x40000];

void init_ignored_retaddr()
{
    // send the address of the retaddr buffer to analyzer.py
    pipe("RET_INIT:%d,%x", GetCurrentProcessId(), retaddr);
}

static void ret_get_flags(unsigned int addr, unsigned int *ignored,
    unsigned int *initialized)
{
    unsigned int index = addr / 0x1000;
    unsigned char info = retaddr[index / 4] >> (index % 4) >> 1;
    // first bit defines whether the address is ignored
    *ignored = info & 1;
    // second bit defines whether the ignored bit has been initialized yet
    *initialized = (info >> 1) & 1;
}

static void ret_set_flags(unsigned int addr, unsigned int ignored)
{
    unsigned int index = addr / 0x1000;
    // reset the original flags
    retaddr[index / 4] &= ~(3 << (index % 4) << 1);
    // set the new flags
    retaddr[index / 4] |= (!!ignored + 2) << (index % 4) << 1;
}

static void ret_check_address(unsigned int addr)
{
    MEMORY_BASIC_INFORMATION mbi;

    // check if we can query information about this address
    if(VirtualQuery((void *) addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        // we cannot query this address (i.e., it doesn't belong to a mapped
        // memory address, and therefore it's blacklisted)
        ret_set_flags(addr, 0);
        return;
    }

    // get the filename of this module
    wchar_t file_name[MAX_PATH];
    if(GetModuleFileNameW(mbi.AllocationBase, file_name,
            ARRAYSIZE(file_name)) == 0) {
        // we cannot obtain the filename of this module, thus it is a
        // dynamically allocated image map, and we blacklist it
        ret_set_flags(addr, 0);
        return;
    }

    // check the dll return address against a list of whitelisted dll's
    // TODO

    // this address appears to be legit
    ret_set_flags(addr, 1);
}

int is_ignored_retaddr(unsigned int addr)
{
    unsigned int ignored, initialized;

    ret_get_flags(addr, &ignored, &initialized);
    if(initialized == 0) {
        ret_check_address(addr);
    }

    ret_get_flags(addr, &ignored, &initialized);
    return ignored;
}
