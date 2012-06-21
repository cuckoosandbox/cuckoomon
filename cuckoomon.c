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

    //
    // File Hooks
    //

    _(ntdll, NtCreateFile),
    _(ntdll, NtOpenFile),
    _(ntdll, NtReadFile),
    _(ntdll, NtWriteFile),

    // lowest variant of MoveFile()
    _(kernel32, MoveFileWithProgressW),

    // perhaps go for NtSetInformationFile() later
    _(kernel32, DeleteFileW),

    //
    // Registry Hooks
    //

    // A does not call W, instead, both go native immediately
    _(advapi32, RegOpenKeyExA),
    _(advapi32, RegOpenKeyExW),

    // same situation as RegOpenKeyEx*, A does not call W
    _(advapi32, RegCreateKeyExA),
    _(advapi32, RegCreateKeyExW),
};

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if(dwReason == DLL_PROCESS_ATTACH) {
        // do stuff
    }
    return TRUE;
}
