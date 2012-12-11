/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2012 Cuckoo Sandbox Developers

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
#include <windows.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"

static IS_SUCCESS_NTSTATUS();
static const char *module_name = "system";

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExA,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
) {
    IS_SUCCESS_HHOOK();
    const char *module_name = "hooking";

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
    IS_SUCCESS_HHOOK();
    const char *module_name = "hooking";

    HHOOK ret = Old_SetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
    LOQ("lppl", "HookIdentifier", idHook, "ProcedureAddress", lpfn,
        "ModuleAddress", hMod, "ThreadId", dwThreadId);
    return ret;
}

HOOKDEF(BOOL, WINAPI, UnhookWindowsHookEx,
  __in  HHOOK hhk
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_UnhookWindowsHookEx(hhk);
    LOQ("p", "HookHandle", hhk);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    ULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
) {
    COPY_UNICODE_STRING(library, ModuleFileName);

    NTSTATUS ret = Old_LdrLoadDll(PathToFile, Flags, ModuleFileName,
        ModuleHandle);
    LOQ("loP", "Flags", Flags, "FileName", &library,
        "BaseAddress", ModuleHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetDllHandle,
    __in_opt    PWORD pwPath,
    __in_opt    PVOID Unused,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE pHModule
) {
    NTSTATUS ret = Old_LdrGetDllHandle(pwPath, Unused, ModuleFileName,
        pHModule);
    LOQ("oP", "FileName", ModuleFileName, "ModuleHandle", pHModule);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddress,
    __in        HMODULE ModuleHandle,
    __in_opt    PANSI_STRING FunctionName,
    __in_opt    WORD Ordinal,
    __out       PVOID *FunctionAddress
) {
    NTSTATUS ret = Old_LdrGetProcedureAddress(ModuleHandle, FunctionName,
        Ordinal, FunctionAddress);
    LOQ("pSl", "ModuleHandle", ModuleHandle,
        "FunctionName", FunctionName != NULL ? FunctionName->Length : 0,
            FunctionName != NULL ? FunctionName->Buffer : NULL,
        "Ordinal", Ordinal);
    return ret;
}

HOOKDEF(BOOL, WINAPI, DeviceIoControl,
  __in         HANDLE hDevice,
  __in         DWORD dwIoControlCode,
  __in_opt     LPVOID lpInBuffer,
  __in         DWORD nInBufferSize,
  __out_opt    LPVOID lpOutBuffer,
  __in         DWORD nOutBufferSize,
  __out_opt    LPDWORD lpBytesReturned,
  __inout_opt  LPOVERLAPPED lpOverlapped
) {
    IS_SUCCESS_BOOL();
    const char *module_name = "device";

    BOOL ret = Old_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
        nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned,
        lpOverlapped);
    LOQ("plbb", "DeviceHandle", hDevice, "IoControlCode", dwIoControlCode,
        "InBuffer", nInBufferSize, lpInBuffer,
        "OutBuffer", lpBytesReturned ? *lpBytesReturned : nOutBufferSize,
            lpOutBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, ExitWindowsEx,
  __in  UINT uFlags,
  __in  DWORD dwReason
) {
    IS_SUCCESS_BOOL();

    int ret = 0;
    LOQ("ll", "Flags", uFlags, "Reason", dwReason);
    return Old_ExitWindowsEx(uFlags, dwReason);
}

HOOKDEF(BOOL, WINAPI, IsDebuggerPresent,
    void
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_IsDebuggerPresent();
    LOQ("");
    return ret;
}

HOOKDEF(BOOL, WINAPI, LookupPrivilegeValueW,
  __in_opt  LPWSTR lpSystemName,
  __in      LPWSTR lpName,
  __out     PLUID lpLuid
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_LookupPrivilegeValueW(lpSystemName, lpName, lpLuid);
    LOQ("uu", "SystemName", lpSystemName, "PrivilegeName", lpName);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtClose,
    __in    HANDLE Handle
) {
    NTSTATUS ret = Old_NtClose(Handle);
    LOQ("p", "Handle", Handle);
    return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleA,
    _In_        HANDLE hConsoleOutput,
    _In_        const VOID *lpBuffer,
    _In_        DWORD nNumberOfCharsToWrite,
    _Out_       LPDWORD lpNumberOfCharsWritten,
    _Reserved_  LPVOID lpReseverd
) {
    BOOL ret = Old_WriteConsoleA(hConsoleOutput, lpBuffer,
        nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
    LOQ("pS", "ConsoleHandle", hConsoleOutput,
        "Buffer", nNumberOfCharsToWrite, lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, WriteConsoleW,
    _In_        HANDLE hConsoleOutput,
    _In_        const VOID *lpBuffer,
    _In_        DWORD nNumberOfCharsToWrite,
    _Out_       LPDWORD lpNumberOfCharsWritten,
    _Reserved_  LPVOID lpReseverd
) {
    BOOL ret = Old_WriteConsoleW(hConsoleOutput, lpBuffer,
        nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReseverd);
    LOQ("pU", "ConsoleHandle", hConsoleOutput,
        "Buffer", nNumberOfCharsToWrite, lpBuffer);
    return ret;
}
