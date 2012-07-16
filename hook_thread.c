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
#include "pipe.h"
#include "misc.h"

static IS_SUCCESS_HANDLE();
static const char *module_name = "threading";

static void notify_pipe(DWORD process_id)
{
    char buf[32] = {}; int len = sizeof(buf);
    pipe_write_read(buf, &len, "PID:%d", process_id);
}

HOOKDEF(HANDLE, WINAPI, OpenThread,
  __in  DWORD dwDesiredAccess,
  __in  BOOL bInheritHandle,
  __in  DWORD dwThreadId
) {
    HANDLE ret = Old_OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    LOQ("ll", "DesiredAccess", dwDesiredAccess, "ThreadId", dwThreadId);
    return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateThread,
  __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
  __in   SIZE_T dwStackSize,
  __in   LPTHREAD_START_ROUTINE lpStartAddress,
  __in   LPVOID lpParameter,
  __in   DWORD dwCreationFlags,
  __out  LPDWORD lpThreadId
) {
    HANDLE ret = Old_CreateThread(lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    LOQ("pplL", "StartRoutine", lpStartAddress, "Parameter", lpParameter,
        "CreationFlags", dwCreationFlags, "ThreadId", lpThreadId);
    return ret;
}

HOOKDEF(HANDLE, WINAPI, CreateRemoteThread,
  __in   HANDLE hProcess,
  __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
  __in   SIZE_T dwStackSize,
  __in   LPTHREAD_START_ROUTINE lpStartAddress,
  __in   LPVOID lpParameter,
  __in   DWORD dwCreationFlags,
  __out  LPDWORD lpThreadId
) {
    notify_pipe(GetPidFromProcessHandle(hProcess));
    HANDLE ret = Old_CreateRemoteThread(hProcess, lpThreadAttributes,
        dwStackSize, lpStartAddress, lpParameter, dwCreationFlags,
        lpThreadId);
    LOQ("3plL", "ProcessHandle", hProcess, "StartRoutine", lpStartAddress,
        "Parameter", lpParameter, "CreationFlags", dwCreationFlags,
        "ThreadId", lpThreadId);
    return ret;
}

HOOKDEF(BOOL, WINAPI, TerminateThread,
  __inout  HANDLE hThread,
  __in     DWORD dwExitCode
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_TerminateThread(hThread, dwExitCode);
    LOQ("pl", "ThreadHandle", hThread, "ExitCode", dwExitCode);
    return ret;
}

HOOKDEF(VOID, WINAPI, ExitThread,
  __in  DWORD dwExitCode
) {
    IS_SUCCESS_VOID();

    int ret = 0;
    LOQ("l", "ExitCode", dwExitCode);
    Old_ExitThread(dwExitCode);
}

HOOKDEF(NTSTATUS, WINAPI, NtGetContextThread,
  __in     HANDLE ThreadHandle,
  __inout  LPCONTEXT Context
) {
    IS_SUCCESS_NTSTATUS();

    NTSTATUS ret = Old_NtGetContextThread(ThreadHandle, Context);
    LOQ("p", "ThreadHandle", ThreadHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetContextThread,
  __in  HANDLE ThreadHandle,
  __in  const CONTEXT *Context
) {
    IS_SUCCESS_NTSTATUS();

    NTSTATUS ret = Old_NtSetContextThread(ThreadHandle, Context);
    LOQ("p", "ThreadHandle", ThreadHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSuspendThread,
  __in          HANDLE ThreadHandle,
  __out_opt     ULONG *PreviousSuspendCount
) {
    IS_SUCCESS_NTSTATUS();

    ENSURE_ULONG(PreviousSuspendCount);

    NTSTATUS ret = Old_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
    LOQ("pL", "ThreadHandle", ThreadHandle,
        "SuspendCount", PreviousSuspendCount);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtResumeThread,
  __in          HANDLE ThreadHandle,
  __out_opt     ULONG *SuspendCount
) {
    IS_SUCCESS_NTSTATUS();

    ENSURE_ULONG(SuspendCount);

    NTSTATUS ret = Old_NtResumeThread(ThreadHandle, SuspendCount);
    LOQ("pL", "ThreadHandle", ThreadHandle, "SuspendCount", SuspendCount);
    return ret;
}
