#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "ntapi.h"

void set_hooks_dll(const wchar_t *library, int len);

HOOKDEF2(NTSTATUS, WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    ULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
) {
    COPY_UNICODE_STRING(library, ModuleFileName);

    NTSTATUS ret = Old2_LdrLoadDll(PathToFile, Flags, ModuleFileName,
        ModuleHandle);

    //
    // Check this DLL against our table of hooks, because we might have to
    // place some new hooks.
    //

    if(NT_SUCCESS(ret)) {
        set_hooks_dll(library.Buffer, library.Length >> 1);
    }

    return ret;
}
