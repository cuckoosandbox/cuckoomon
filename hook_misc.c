#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExA,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
) {
    HHOOK ret = Old_SetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);
    LOQ("lppl", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
        "ModuleAddress", hMod, "ThreadId", dwThreadId);
    return ret;
}

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExW,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
) {
    HHOOK ret = Old_SetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
    LOQ("lppl", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
        "ModuleAddress", hMod, "ThreadId", dwThreadId);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    ULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
) {
    NTSTATUS ret = Old_LdrLoadDll(PathToFile, Flags, ModuleFileName,
        ModuleHandle);
    LOQ("uloP", "FilePath", PathToFile, "Flags", Flags,
        "FileName", ModuleFileName, "BaseAddress", ModuleHandle);
    return ret;
}
