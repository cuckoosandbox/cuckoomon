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
#include "hooking.h"
#include "hooks.h"
#include "misc.h"

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

uint8_t *generate_stub_function(const uint8_t *orig_func, uint8_t *new_func)
{
    int esp_cleanup = 0, pushed_reg[8] = {};
    for (int required_length = 5, length; required_length > 0;
            orig_func += length, required_length -= length) {
        length = lde(orig_func);

        // error?
        if(length == 0) {
            return NULL;
        }

        // now we have to copy some instructions in order to make our
        // function look legit
        // mov edi, edi and nop and mov (eax|ecx|edx|ebx), imm32
        if((*orig_func == 0x8b && orig_func[1] == 0xff) ||
                *orig_func == 0x90 ||
                (*orig_func >= 0xb8 && *orig_func <= 0xbb)) {
            memcpy(new_func, orig_func, length);
            new_func += length;
        }
        // push eax..edi
        else if(*orig_func >= 0x50 && *orig_func < 0x58) {
            *new_func++ = *orig_func;
            esp_cleanup += 4;

            // keep track at which stack pointer offset this register is
            // pushed
            pushed_reg[*orig_func - 0x50] = esp_cleanup;
        }
        // mov ebp, esp
        else if(*orig_func == 0x8b && orig_func[1] == 0xec) {
            memcpy(new_func, orig_func, length);
            new_func += length;
        }
        // sub esp, abc
        else if(*orig_func == 0x83 && orig_func[1] == 0xec) {
            memcpy(new_func, orig_func, length);
            esp_cleanup += orig_func[2];
        }
        else {
            return NULL;
        }
    }

    // we've copied the function stub, now let's clean it up
    if(esp_cleanup != 0) {
        // add esp, esp_cleanup
        *new_func++ = 0x81;
        *new_func++ = 0xc4;
        *(uint32_t *) new_func = esp_cleanup;
        new_func += 4;
    }

    // restore registers that were pushed to the stack
    for (uint32_t i = 0; i < 8; i++) {
        if(pushed_reg[i] != 0) {
            // mov reg32, dword [esp-offset]
            *new_func++ = 0x8b;
            *new_func++ = 0x44 + 8 * i;
            *new_func++ = 0xe4;
            *new_func++ = 0x100 - pushed_reg[i];
        }
    }

    // return the address of the end of the function stub
    return new_func;
}

static void *generate_stubdll(void *image, uint32_t *image_size,
    const wchar_t *library, int liblen)
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
    uint32_t section_size = 64 * export_directory->NumberOfFunctions +
        export_data_directory->Size;
    *image_size = 1024 + section_size;

    // initially allocate everything as RWX
    unsigned char *stub_dll = VirtualAlloc(NULL, *image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // set all bytes to int3, so we see it when something goes wrong
    memset(stub_dll, 0xcc, *image_size);

    // copy the image dos header and whatever is between the image dos header
    // and the image nt headers
    memcpy(stub_dll, image_dos_header, image_dos_header->e_lfanew);

    // copy the image nt headers
    IMAGE_NT_HEADERS *new_nt_headers = (IMAGE_NT_HEADERS *)(
        stub_dll + image_dos_header->e_lfanew);
    memcpy(new_nt_headers, image_nt_headers, sizeof(IMAGE_NT_HEADERS));

    // alter some fields of the new nt headers
    new_nt_headers->FileHeader.NumberOfSections = 1;
    new_nt_headers->FileHeader.PointerToSymbolTable = 0;
    new_nt_headers->FileHeader.NumberOfSymbols = 0;
    new_nt_headers->OptionalHeader.NumberOfRvaAndSizes =
        IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    // reset the data directories
    memset(new_nt_headers->OptionalHeader.DataDirectory, 0,
        sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    // update the data directory to point the export table to our newly
    // generated table (see below)
    IMAGE_DATA_DIRECTORY *new_data_directory =
        new_nt_headers->OptionalHeader.DataDirectory;

    IMAGE_DATA_DIRECTORY *new_export_data_directory =
        &new_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    new_export_data_directory->VirtualAddress = 1024;
    new_export_data_directory->Size = export_data_directory->Size;

    // generate the text section
    IMAGE_SECTION_HEADER image_section_header = {
        .Name               = ".text",
        .Misc.VirtualSize   = section_size,
        .VirtualAddress     = 1024,
        .SizeOfRawData      = section_size,
        .PointerToRawData   = 1024,
        .Characteristics    =
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    };

    // copy the section to the right place
    memcpy(IMAGE_FIRST_SECTION(new_nt_headers), &image_section_header,
        sizeof(image_section_header));

    // first let's setup the export table
    IMAGE_EXPORT_DIRECTORY image_export_directory = {
        .Characteristics        = export_directory->Characteristics,
        .TimeDateStamp          = export_directory->TimeDateStamp,
        .MajorVersion           = export_directory->MajorVersion,
        .MinorVersion           = export_directory->MinorVersion,
        .Name                   = export_directory->Name +
            (uint32_t) image - (uint32_t) stub_dll,
        .Base                   = 1, // TODO is this correct?
        .NumberOfFunctions      = export_directory->NumberOfFunctions,
        .NumberOfNames          = export_directory->NumberOfNames,
        // addressoffunctions is right after the image export directory
        .AddressOfFunctions     = 1024 + sizeof(image_export_directory),
        .AddressOfNames         = 1024 + sizeof(image_export_directory) +
            sizeof(uint32_t) * export_directory->NumberOfFunctions,
        .AddressOfNameOrdinals  = export_directory->AddressOfNameOrdinals +
            (uint32_t) image - (uint32_t) stub_dll,
    };

    memcpy(stub_dll + 1024, &image_export_directory,
        sizeof(image_export_directory));

    // now set all the function addresses correctly up
    uint32_t *address_of_functions = (uint32_t *)(stub_dll + 1024 +
        sizeof(image_export_directory));

    // points to the address of each stub function
    uint8_t *function = (uint8_t *)(
        address_of_functions + export_directory->NumberOfFunctions +
        export_directory->NumberOfNames);

    // original table of function addresses
    uint32_t *orig_function_addresses = (uint32_t *)(
        (char *) image + export_directory->AddressOfFunctions);

    // our table of names, which we will want to point to the original dll
    uint32_t *address_of_names = (uint32_t *)(stub_dll + 1024 +
        sizeof(image_export_directory) +
        sizeof(uint32_t) * export_directory->NumberOfFunctions);

    // original table of names addresses
    uint32_t *orig_names_addresses = (uint32_t *)(
        (char *) image + export_directory->AddressOfNames);

    uint16_t *orig_address_of_name_ordinals = (uint16_t *)(
        (char *) image + export_directory->AddressOfNameOrdinals);

    for (int i = 0; i < export_directory->NumberOfNames; i++) {
        address_of_names[i] = orig_names_addresses[i] +
            (uint32_t) image - (uint32_t) stub_dll;
    }

    // what could possibly go wrong?
    uint8_t *func_table[export_directory->NumberOfFunctions];

    for (int i = 0; i < export_directory->NumberOfFunctions; i++) {
        // original function address
        uint8_t *orig_addr = (uint8_t *) image + orig_function_addresses[i];

        uint32_t function_offset = orig_function_addresses[i];

        // check if this function is being forwarded, which is the case when
        // the address is within the range of the image export data entry
        if(function_offset >= export_data_directory->VirtualAddress &&
                function_offset < export_data_directory->VirtualAddress +
                    export_data_directory->Size) {
            // TODO add real support for forwarded functions
            func_table[i] = NULL;
            *address_of_functions++ = 0;
            continue;
        }

        // now generate a stub function
        uint8_t *func_stub = generate_stub_function(orig_addr, function);

        // temporarily store the function stub address in the table
        func_table[i] = func_stub;

        // place the relative address of the new function in our function
        // address table
        *address_of_functions++ = function - stub_dll;

        // we've decided upfront that every function may take upto 64 bytes
        function += 64;
    }

    // now we're going to cross-reference the function stubs in the function
    // table against the list of function names, in order to check whether
    // functions have to be hooked
    for (int i = 0; i < export_directory->NumberOfNames; i++) {
        // function name
        const char *funcname = (const char *) image + orig_names_addresses[i];

        // original function address
        uint8_t *orig_addr = (uint8_t *) image + orig_function_addresses[i];

        // lookup if we want to hook this function
        hook_t *h = get_function_hook(library, liblen, funcname);
        if(h != NULL) {

            uint8_t *func_stub = func_table[orig_address_of_name_ordinals[i]];

            *func_stub = 0xe9;
            *(uint32_t *) &func_stub[1] =
                (uint8_t *) h->new_func - func_stub - 5;

            // TODO is this correct?
            *h->old_func = orig_addr;

            func_table[orig_address_of_name_ordinals[i]] = NULL;
        }
    }

    // we have to add a jump to original functions to all functions that are
    // *not* hooked
    for (int i = 0; i < export_directory->NumberOfFunctions; i++) {
        if(func_table[i] != NULL) {
            // original function address
            uint8_t *orig_addr =
                (uint8_t *) image + orig_function_addresses[i];

            uint8_t *func_stub = func_table[i];
            *func_stub = 0xe9;
            *(uint32_t *) &func_stub[1] = orig_addr - func_stub - 5;
        }
    }
    return stub_dll;
}

static void NTAPI init_modules(LDR_DATA_TABLE_ENTRY *ldr_entry, void *context,
    BOOLEAN *stop)
{
    *stop = FALSE;

    // if we don't have hooks for this library, then there's no need to make
    // a stubdll for it
    if(!has_library_hooks(ldr_entry->BaseDllName.Buffer,
            ldr_entry->BaseDllName.Length / sizeof(wchar_t))) {
        return;
    }

    void *new_dll; uint32_t image_size;

    new_dll = generate_stubdll(ldr_entry->DllBase, &image_size,
        ldr_entry->BaseDllName.Buffer,
        ldr_entry->BaseDllName.Length / sizeof(wchar_t));

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
    if(ldr_entry->DllBase == *addr) {

        *stop = TRUE;

        // if we don't have hooks for this library, then there's no need to
        // make a stubdll for it
        if(!has_library_hooks(ldr_entry->BaseDllName.Buffer,
                ldr_entry->BaseDllName.Length / sizeof(wchar_t))) {
            return;
        }

        void *new_dll; uint32_t image_size;

        new_dll = generate_stubdll(*addr, &image_size,
            ldr_entry->BaseDllName.Buffer,
            ldr_entry->BaseDllName.Length / sizeof(wchar_t));

        ldr_entry->DllBase = new_dll;
        ldr_entry->SizeOfImage = image_size;

        stubdll_t dll = {
            .real_address = *addr,
            .stub_address = new_dll,
        };

        add_entry(&dll);

        *addr = new_dll;
    }
    else {
        *stop = FALSE;
    }
}

// to alter the return address of LdrLoadDll
void stubdll_loadlib(HMODULE *image)
{
    if(has_entry(*image, image)) {
        return;
    }

    pLdrEnumerateLoadedModules(FALSE, &update_modules, image);
}
