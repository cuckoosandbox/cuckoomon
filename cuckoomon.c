#include <stdio.h>
#include <windows.h>
#include "ntapi.h"
#include "hooking.h"
#include "hooks.h"

#define HOOK(library, funcname) {#library, #funcname, NULL, &New_##funcname, \
    (void **) &Old_##funcname}

static hook_t g_hooks[] = {

    //
    // File Hooks
    //

    HOOK(ntdll, NtCreateFile),
    HOOK(ntdll, NtOpenFile),
    HOOK(ntdll, NtReadFile),
    HOOK(ntdll, NtWriteFile),

    // lowest variant of MoveFile()
    HOOK(kernel32, MoveFileWithProgressW),

    // perhaps go for NtSetInformationFile() later
    HOOK(kernel32, DeleteFileW),

    //
    // Registry Hooks
    //
    // Note: Most, if not all, of the Registry API go natively from both the
    // A as well as the W versions. In other words, we have to hook all the
    // ascii *and* unicode APIs of those functions.
    //

    HOOK(advapi32, RegOpenKeyExA),
    HOOK(advapi32, RegOpenKeyExW),

    HOOK(advapi32, RegCreateKeyExA),
    HOOK(advapi32, RegCreateKeyExW),

    // Note that RegDeleteKeyEx() is available for 64bit XP/Vista+
    HOOK(advapi32, RegDeleteKeyA),
    HOOK(advapi32, RegDeleteKeyW),

    // RegEnumKeyA() calls RegEnumKeyExA(), but RegEnumKeyW() does *not*
    // call RegEnumKeyExW()
    HOOK(advapi32, RegEnumKeyW),
    HOOK(advapi32, RegEnumKeyExA),
    HOOK(advapi32, RegEnumKeyExW),

    HOOK(advapi32, RegEnumValueA),
    HOOK(advapi32, RegEnumValueW),

    HOOK(advapi32, RegSetValueExA),
    HOOK(advapi32, RegSetValueExW),

    HOOK(advapi32, RegQueryValueExA),
    HOOK(advapi32, RegQueryValueExW),

    HOOK(advapi32, RegDeleteValueA),
    HOOK(advapi32, RegDeleteValueW),

    //
    // Window Hooks
    //

    HOOK(user32, FindWindowA),
    HOOK(user32, FindWindowW),
    HOOK(user32, FindWindowExA),
    HOOK(user32, FindWindowExW),

    //
    // Sync Hooks
    //

    HOOK(ntdll, NtCreateMutant),
    HOOK(ntdll, NtOpenMutant),

    //
    // Process Hooks
    //

    HOOK(ntdll, NtCreateProcess),
    HOOK(ntdll, NtCreateProcessEx),
    HOOK(kernel32, CreateProcessInternalW),
    HOOK(kernel32, OpenProcess),
    HOOK(kernel32, TerminateProcess),
    HOOK(kernel32, ExitProcess),

    // all variants of ShellExecute end up in ShellExecuteExW
    HOOK(shell32, ShellExecuteExW),
};

void set_hooks()
{
    // the hooks contain the gates as well, so they have to be RWX
    DWORD old_protect;
    VirtualProtect(g_hooks, sizeof(g_hooks), PAGE_EXECUTE_READWRITE,
        &old_protect);

    // now, hook each api :)
    for (int i = 0; i < ARRAYSIZE(g_hooks); i++) {
        hook_t *h = &g_hooks[i];

        // we have to manually locate the address of CreateProcessInternalW,
        // because it's not exported in the export address table. we can find
        // the address in the CreateProcessW function, as it's the only
        // address being called in that function, so we will just do a
        // cross-reference there

        if(!strcmp(h->library, "kernel32") && !strcmp(h->library,
                "CreateProcessInternalW")) {

            unsigned char *addr = (unsigned char *) GetProcAddress(
                GetModuleHandle("kernel32"), "CreateProcessW");

            // max 20 instructions before we reach the call instruction
            for (int i = 0; i < 20; i++) {
                if(*addr == 0xe8) {
                    // we have found the address of CreateProcessInternalW
                    h->addr = addr + *(unsigned long *)(addr + 1) + 5;
                    break;
                }

                // iterate to the next instruction
                addr += lde(addr);
            }
        }

        hook_api(&g_hooks[i], HOOK_DIRECT_JMP);
    }
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if(dwReason == DLL_PROCESS_ATTACH) {
        set_hooks();
    }
    return TRUE;
}
