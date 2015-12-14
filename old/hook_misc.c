/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

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
#include "pipe.h"
#include "misc.h"
#include "hook_file.h"
#include "hook_sleep.h"

static IS_SUCCESS_NTSTATUS();

HOOKDEF(HHOOK, WINAPI, SetWindowsHookExA,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
) {
    IS_SUCCESS_HHOOK();

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
    LOQ("pSlP", "ModuleHandle", ModuleHandle,
        "FunctionName", FunctionName != NULL ? FunctionName->Length : 0,
            FunctionName != NULL ? FunctionName->Buffer : NULL,
        "Ordinal", Ordinal, "FunctionAddress", FunctionAddress);
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
    if(NT_SUCCESS(ret)) {
        file_close(Handle);
    }
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

HOOKDEF(NTSTATUS, WINAPI, ZwMapViewOfSection,
    _In_     HANDLE SectionHandle,
    _In_     HANDLE ProcessHandle,
    __inout  PVOID *BaseAddress,
    _In_     ULONG_PTR ZeroBits,
    _In_     SIZE_T CommitSize,
    __inout  PLARGE_INTEGER SectionOffset,
    __inout  PSIZE_T ViewSize,
    __in     UINT InheritDisposition,
    __in     ULONG AllocationType,
    __in     ULONG Win32Protect
) {
    NTSTATUS ret = Old_ZwMapViewOfSection(SectionHandle, ProcessHandle,
        BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
        InheritDisposition, AllocationType, Win32Protect);
    LOQ("ppPp", "SectionHandle", SectionHandle,
        "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "SectionOffset", SectionOffset);

    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(int, WINAPI, GetSystemMetrics,
    _In_  int nIndex
) {
    int ret = Old_GetSystemMetrics(nIndex);
    LOQ("l", "SystemMetricIndex", nIndex);
    return ret;
}

HOOKDEF(BOOL, WINAPI, GetCursorPos,
    _Out_ LPPOINT lpPoint
) {
    BOOL ret = Old_GetCursorPos(lpPoint);
    LOQ("ll", "x", lpPoint != NULL ? lpPoint->x : 0,
        "y", lpPoint != NULL ? lpPoint->y : 0);
    return ret;
}
