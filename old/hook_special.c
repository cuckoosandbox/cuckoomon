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
#include "hook_sleep.h"

static IS_SUCCESS_NTSTATUS();

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

    if (hook_info()->depth_count == 1) {
        LOQspecial("loP", "Flags", Flags, "FileName", &library,
            "BaseAddress", ModuleHandle);
    }

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

    if (hook_info()->depth_count == 1) {
        LOQspecial("uupllpp", "ApplicationName", lpApplicationName,
            "CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
            "ProcessId", lpProcessInformation->dwProcessId,
            "ThreadId", lpProcessInformation->dwThreadId,
            "ProcessHandle", lpProcessInformation->hProcess,
            "ThreadHandle", lpProcessInformation->hThread);
    }

    return ret;
}
