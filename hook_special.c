#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"
#include "pipe.h"
#include "hook_sleep.h"

void set_hooks_dll(const wchar_t *library, int len);

HOOKDEF2(NTSTATUS, WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    ULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
) {
    //
    // In the event that loading this dll results in loading another dll as
    // well, then the unicode string (which is located in the TEB) will be
    // overwritten, therefore we make a copy of it for our own use.
    //

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

HOOKDEF2(BOOL, WINAPI, CreateProcessInternalW,
    __in_opt    LPVOID lpUnknown1,
    __in_opt    LPWSTR lpApplicationName,
    __inout_opt LPWSTR lpCommandLine,
    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    __in        BOOL bInheritHandles,
    __in        DWORD dwCreationFlags,
    __in_opt    LPVOID lpEnvironment,
    __in_opt    LPWSTR lpCurrentDirectory,
    __in        LPSTARTUPINFO lpStartupInfo,
    __out       LPPROCESS_INFORMATION lpProcessInformation,
    __in_opt    LPVOID lpUnknown2
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old2_CreateProcessInternalW(lpUnknown1, lpApplicationName,
        lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation, lpUnknown2);
    if(ret != FALSE) {
        pipe("PROCESS:%d,%d", lpProcessInformation->dwProcessId,
            lpProcessInformation->dwThreadId);

        // if the CREATE_SUSPENDED flag was not set, then we have to resume
        // the main thread ourself
        if((dwCreationFlags & CREATE_SUSPENDED) == 0) {
            ResumeThread(lpProcessInformation->hThread);
        }

        disable_sleep_skip();
    }
    return ret;
}
