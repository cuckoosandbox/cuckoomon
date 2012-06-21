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
    // Note: Most, if not all, of the Registry API go natively from both the
    // A as well as the W versions. In other words, we have to hook all the
    // ascii *and* unicode APIs of those functions.
    //

    _(advapi32, RegOpenKeyExA),
    _(advapi32, RegOpenKeyExW),

    _(advapi32, RegCreateKeyExA),
    _(advapi32, RegCreateKeyExW),

    // Note that RegDeleteKeyEx() is available for 64bit XP/Vista+
    _(advapi32, RegDeleteKeyA),
    _(advapi32, RegDeleteKeyW),

    // RegEnumKeyA() calls RegEnumKeyExA(), but RegEnumKeyW() does *not*
    // call RegEnumKeyExW()
    _(advapi32, RegEnumKeyW),
    _(advapi32, RegEnumKeyExA),
    _(advapi32, RegEnumKeyExW),

    _(advapi32, RegEnumValueA),
    _(advapi32, RegEnumValueW),

    _(advapi32, RegSetValueExA),
    _(advapi32, RegSetValueExW),

    _(advapi32, RegQueryValueExA),
    _(advapi32, RegQueryValueExW),

    _(advapi32, RegDeleteValueA),
    _(advapi32, RegDeleteValueW),
};

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if(dwReason == DLL_PROCESS_ATTACH) {
        // do stuff
    }
    return TRUE;
}
