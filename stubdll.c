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
#include <stdint.h>
#include <windows.h>
#include "ntapi.h"
#include "stubdll.h"

typedef struct _stubdll_t {
    HMODULE real_address;
    HMODULE stub_address;
} stubdll_t;

static stubdll_t *g_stubdlls;
static int g_stubdll_count;
static CRITICAL_SECTION g_cs;

static NTSTATUS (NTAPI *pLdrEnumerateLoadedModules)(
    IN BOOLEAN              ReservedFlag,
    IN LDR_ENUM_CALLBACK   *EnumProc,
    IN PVOID                Context);

static void add_entry(const stubdll_t *dll)
{
    EnterCriticalSection(&g_cs);

    g_stubdlls = (stubdll_t *) realloc(g_stubdlls,
        sizeof(stubdll_t) * (g_stubdll_count + 1));

    memcpy(&g_stubdlls[g_stubdll_count++], dll, sizeof(stubdll_t));

    LeaveCriticalSection(&g_cs);
}

static int has_entry(void *address, HMODULE *stub_address)
{
    EnterCriticalSection(&g_cs);

    int ret = 0;

    for (int i = 0; i < g_stubdll_count; i++) {
        if(address == g_stubdlls[i].real_address ||
                address == g_stubdlls[i].stub_address) {
            ret = 1;
            *stub_address = g_stubdlls[i].stub_address;
            break;
        }
    }

    LeaveCriticalSection(&g_cs);
    return ret;
}

static void *generate_stubdll(void *image, uint32_t *image_size)
{
    IMAGE_DOS_HEADER *image_dos_header = (IMAGE_DOS_HEADER *) image;
    IMAGE_NT_HEADERS *image_nt_headers =
        (IMAGE_NT_HEADERS *)((char *) image + image_dos_header->e_lfanew);

    IMAGE_DATA_DIRECTORY *data_directories =
        image_nt_headers->OptionalHeader.DataDirectory;

    IMAGE_DATA_DIRECTORY *export_data_directory =
        &data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];

    IMAGE_EXPORT_DIRECTORY *export_directory = (IMAGE_EXPORT_DIRECTORY *)(
        (char *) image + export_data_directory->VirtualAddress);

    // calculate the required size, 1024 for the headers (image dos header,
    // image nt headers, one image section header), 64 bytes for every
    // function stub, and then the export table (which we pretty much copy
    // directly)
    uint32_t required_size = 1024 + 64 * export_directory->NumberOfFunctions +
        export_data_directory->Size;

    // initially allocate everything as RWX
    unsigned char *stub_dll = VirtualAlloc(NULL, required_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // copy the image dos header
    memcpy(stub_dll, image_dos_header, sizeof(IMAGE_DOS_HEADER));

    // copy whatever is between the image dos header and the image nt headers
    memcpy(stub_dll + sizeof(IMAGE_DOS_HEADER), image_dos_header + 1,
        image_dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));

    // copy the image nt headers
    IMAGE_NT_HEADERS *new_nt_headers = (IMAGE_NT_HEADERS *)(
        stub_dll + image_dos_header->e_lfanew);
    memcpy(new_nt_headers, image_nt_headers, sizeof(IMAGE_NT_HEADERS));

    // alter some fields of the new nt headers
    new_nt_headers->FileHeader.NumberOfSections = 1;
    new_nt_headers->FileHeader.PointerToSymbolTable = 0;
    new_nt_headers->FileHeader.NumberOfSymbols = 0;

    // reset the data directories
    memset(new_nt_headers->OptionalHeader.DataDirectory, 0,
        sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);


}

static void NTAPI init_modules(LDR_DATA_TABLE_ENTRY *ldr_entry, void *context,
    BOOLEAN *stop)
{
    *stop = FALSE;

    void *new_dll; uint32_t image_size;

    new_dll = generate_stubdll(ldr_entry->DllBase, &image_size);

    stubdll_t dll = {
        .real_address = ldr_entry->DllBase,
        .stub_address = new_dll,
    };

    add_entry(&dll);

    ldr_entry->DllBase = new_dll;
    ldr_entry->SizeOfImage = image_size;
}

// initialize once, so we can update all existing dlls with stubs
void stubdll_init()
{
    InitializeCriticalSection(&g_cs);

    *(FARPROC *) &pLdrEnumerateLoadedModules = GetProcAddress(
        GetModuleHandle("ntdll"), "LdrEnumerateLoadedModules");

    pLdrEnumerateLoadedModules(FALSE, &init_modules, NULL);
}

static void NTAPI update_modules(LDR_DATA_TABLE_ENTRY *ldr_entry,
    void *context, BOOLEAN *stop)
{
    void **addr = context;
    if(ldr_entry->DllBase == addr[0]) {
        ldr_entry->DllBase = addr[1];
        ldr_entry->SizeOfImage = (uint32_t) addr[2];
        *stop = TRUE;
    }
    else {
        *stop = FALSE;
    }
}

// to alter the return address of LdrLoadDll
void stubdll_loadlib(HMODULE *image)
{
    void *new_dll; uint32_t image_size;

    if(has_entry(*image, image)) {
        return;
    }

    new_dll = generate_stubdll(*image, &image_size);

    stubdll_t dll = {
        .real_address = *image,
        .stub_address = new_dll,
    };

    add_entry(&dll);

    void *addr[3] = {*image, new_dll, (void *) image_size};
    pLdrEnumerateLoadedModules(FALSE, &update_modules, addr);

    *image = new_dll;
}
