#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "ntapi.h"

HOOKDEF2(NTSTATUS, WINAPI, NtResumeThread,
    __in        HANDLE ThreadHandle,
    __out_opt   PULONG SuspendCount
) {
    //
    // If this ThreadHandle points to the main thread of a newly created
    // process, then we will want to inject our dll into the new process at
    // this point.
    //

    NTSTATUS ret = Old2_NtResumeThread(ThreadHandle, SuspendCount);
    return ret;
}

HOOKDEF2(NTSTATUS, WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    ULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
) {
    NTSTATUS ret = Old2_LdrLoadDll(PathToFile, Flags, ModuleFileName,
        ModuleHandle);

    //
    // Check this DLL against our table of hooks, because we might have to
    // place some new hooks.
    //

    return ret;
}
