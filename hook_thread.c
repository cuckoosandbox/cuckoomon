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
#include "hook_sleep.h"

static IS_SUCCESS_NTSTATUS();

HOOKDEF(NTSTATUS, WINAPI, NtCreateThread,
    __out     PHANDLE ThreadHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
    __in      HANDLE ProcessHandle,
    __out     PCLIENT_ID ClientId,
    __in      PCONTEXT ThreadContext,
    __in      PINITIAL_TEB InitialTeb,
    __in      BOOLEAN CreateSuspended
) {
    pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));

    NTSTATUS ret = Old_NtCreateThread(ThreadHandle, DesiredAccess,
        ObjectAttributes, ProcessHandle, ClientId, ThreadContext,
        InitialTeb, CreateSuspended);
    LOQ("PpO", "ThreadHandle", ThreadHandle, "ProcessHandle", ProcessHandle,
        "ObjectAttributes", ObjectAttributes);
    if(NT_SUCCESS(ret)) {
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateThreadEx,
    OUT     PHANDLE hThread,
    IN      ACCESS_MASK DesiredAccess,
    IN      PVOID ObjectAttributes,
    IN      HANDLE ProcessHandle,
    IN      LPTHREAD_START_ROUTINE lpStartAddress,
    IN      PVOID lpParameter,
    IN      BOOL CreateSuspended,
    IN      LONG StackZeroBits,
    IN      LONG SizeOfStackCommit,
    IN      LONG SizeOfStackReserve,
    OUT     PVOID lpBytesBuffer
) {
    NTSTATUS ret = Old_NtCreateThreadEx(hThread, DesiredAccess,
        ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter,
        CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve,
        lpBytesBuffer);
    LOQ("Pppl", "ThreadHandle", hThread, "ProcessHandle", ProcessHandle,
        "StartAddress", lpStartAddress, "CreateSuspended", CreateSuspended);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenThread,
    __out  PHANDLE ThreadHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __in   PCLIENT_ID ClientId
) {
    NTSTATUS ret = Old_NtOpenThread(ThreadHandle, DesiredAccess,
        ObjectAttributes, ClientId);
    LOQ("PlO", "ThreadHandle", ThreadHandle, "DesiredAccess", DesiredAccess,
        "ObjectAttributes", ObjectAttributes);
    if(NT_SUCCESS(ret)) {
        // TODO: are we sure that OpenThread specifies the PID?
        pipe("PROCESS:%d", ClientId->UniqueProcess);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtGetContextThread,
    __in     HANDLE ThreadHandle,
    __inout  LPCONTEXT Context
) {
    NTSTATUS ret = Old_NtGetContextThread(ThreadHandle, Context);
    LOQ("p", "ThreadHandle", ThreadHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetContextThread,
    __in  HANDLE ThreadHandle,
    __in  const CONTEXT *Context
) {
    NTSTATUS ret = Old_NtSetContextThread(ThreadHandle, Context);
    LOQ("p", "ThreadHandle", ThreadHandle);

    pipe("PROCESS:%d", pid_from_thread_handle(ThreadHandle));
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSuspendThread,
    __in        HANDLE ThreadHandle,
    __out_opt   ULONG *PreviousSuspendCount
) {
    ENSURE_ULONG(PreviousSuspendCount);

    NTSTATUS ret = Old_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
    LOQ("pL", "ThreadHandle", ThreadHandle,
        "SuspendCount", PreviousSuspendCount);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtResumeThread,
    __in        HANDLE ThreadHandle,
    __out_opt   ULONG *SuspendCount
) {
    ENSURE_ULONG(SuspendCount);

    NTSTATUS ret = Old_NtResumeThread(ThreadHandle, SuspendCount);
    LOQ("pL", "ThreadHandle", ThreadHandle, "SuspendCount", SuspendCount);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtTerminateThread,
    __in  HANDLE ThreadHandle,
    __in  NTSTATUS ExitStatus
) {
    NTSTATUS ret = Old_NtTerminateThread(ThreadHandle, ExitStatus);
    LOQ("pl", "ThreadHandle", ThreadHandle, "ExitStatus", ExitStatus);
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
    IS_SUCCESS_HANDLE();

    HANDLE ret = Old_CreateThread(lpThreadAttributes, dwStackSize,
        lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    LOQ("pplL", "StartRoutine", lpStartAddress, "Parameter", lpParameter,
        "CreationFlags", dwCreationFlags, "ThreadId", lpThreadId);
    if(NT_SUCCESS(ret)) {
        disable_sleep_skip();
    }
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
    IS_SUCCESS_HANDLE();

    pipe("PROCESS:%d", pid_from_process_handle(hProcess));

    HANDLE ret = Old_CreateRemoteThread(hProcess, lpThreadAttributes,
        dwStackSize, lpStartAddress, lpParameter, dwCreationFlags,
        lpThreadId);
    LOQ("3plL", "ProcessHandle", hProcess, "StartRoutine", lpStartAddress,
        "Parameter", lpParameter, "CreationFlags", dwCreationFlags,
        "ThreadId", lpThreadId);
    if(NT_SUCCESS(ret)) {
        disable_sleep_skip();
    }
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

HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserThread,
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientId
) {
    ENSURE_CLIENT_ID(ClientId);

    NTSTATUS ret = Old_RtlCreateUserThread(ProcessHandle, SecurityDescriptor,
        CreateSuspended, StackZeroBits, StackReserved, StackCommit,
        StartAddress, StartParameter, ThreadHandle, ClientId);
    LOQ("plppPl", "ProcessHandle", ProcessHandle,
        "CreateSuspended", CreateSuspended, "StartAddress", StartAddress,
        "StartParameter", StartParameter, "ThreadHandle", ThreadHandle,
        "ThreadIdentifier", ClientId->UniqueThread);
    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:0,%d", ClientId->UniqueThread);
        disable_sleep_skip();
    }
    return ret;
}
