#include <stdio.h>
#include <windows.h>
#include "hooking.h"

// direct 0xe9 jmp
static int _hook_api_jmp_direct(hook_t *h)
{
    FARPROC addr = GetProcAddress(GetModuleHandle(h->library), h->funcname);
    if(addr == NULL) return 0;

    DWORD old_protect;
    if(VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
        unsigned char *p = (unsigned char *) addr;

        // TODO make a backup of the first few instructions
        // ...

        // jmp opcode
        *p = 0xe9;

        // store the relative address from this opcode to our hook function
        *(unsigned long *)(p + 1) = (unsigned char *) h->new_func - p - 5;
        return 1;
    }
    return 0;
}

int hook_api(hook_t *h)
{
    // default hooking type at the moment
    return _hook_api_jmp_direct(h);
}

