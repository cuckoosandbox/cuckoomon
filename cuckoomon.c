#include <stdio.h>
#include <windows.h>
#include "ntapi.h"
#include "hooks.h"

typedef struct _hook_t {
    const char *library;
    const char *funcname;

    // pointer to the new function
    void *new_func;

    // "function" which jumps over the trampoline and executes the original
    // function call
    void *old_func;
} hook_t;

#define _(library, funcname) {#library, #funcname, &New_##funcname, \
    &Old_##funcname}

static hook_t g_hooks[] = {
    _(ntdll, NtCreateFile),
    _(ntdll, NtOpenFile),
    _(ntdll, NtReadFile),
    _(ntdll, NtWriteFile),

    // lowest variant of MoveFile()
    _(kernel32, MoveFileWithProgressW),

    // perhaps go for NtSetInformationFile() later
    _(kernel32, DeleteFileW),
};

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if(dwReason == DLL_PROCESS_ATTACH) {
        // do stuff
    }
    return TRUE;
}
