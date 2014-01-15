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
#include "ignore.h"
#include "hook_sleep.h"

static IS_SUCCESS_NTSTATUS();

HOOKDEF(NTSTATUS, WINAPI, NtCreateProcess,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        BOOLEAN InheritObjectTable,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort
) {
    NTSTATUS ret = Old_NtCreateProcess(ProcessHandle, DesiredAccess,
        ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle,
        DebugPort, ExceptionPort);
    LOQ("PpO", "ProcessHandle", ProcessHandle, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes);
    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d", pid_from_process_handle(*ProcessHandle));
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateProcessEx,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        ULONG Flags,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort,
    __in        BOOLEAN InJob
) {
    NTSTATUS ret = Old_NtCreateProcessEx(ProcessHandle, DesiredAccess,
        ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort,
        ExceptionPort, InJob);
    LOQ("PpO", "ProcessHandle", ProcessHandle, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes);
    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d", pid_from_process_handle(*ProcessHandle));
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateUserProcess,
    __out       PHANDLE ProcessHandle,
    __out       PHANDLE ThreadHandle,
    __in        ACCESS_MASK ProcessDesiredAccess,
    __in        ACCESS_MASK ThreadDesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    __in_opt    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    __in        ULONG ProcessFlags,
    __in        ULONG ThreadFlags,
    __in_opt    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    __inout     PPS_CREATE_INFO CreateInfo,
    __in_opt    PPS_ATTRIBUTE_LIST AttributeList
) {
    RTL_USER_PROCESS_PARAMETERS _ProcessParameters = {};
    if(ProcessParameters == NULL) ProcessParameters = &_ProcessParameters;

    NTSTATUS ret = Old_NtCreateUserProcess(ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags, ThreadFlags, ProcessParameters,
        CreateInfo, AttributeList);
    LOQ("PPppOOoo", "ProcessHandle", ProcessHandle,
        "ThreadHandle", ThreadHandle,
        "ProcessDesiredAccess", ProcessDesiredAccess,
        "ThreadDesiredAccess", ThreadDesiredAccess,
        "ProcessFileName", ProcessObjectAttributes,
        "ThreadName", ThreadObjectAttributes,
        "ImagePathName", &ProcessParameters->ImagePathName,
        "CommandLine", &ProcessParameters->CommandLine);
    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d,%d", pid_from_process_handle(*ProcessHandle),
            pid_from_thread_handle(*ThreadHandle));
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserProcess,
    IN      PUNICODE_STRING ImagePath,
    IN      ULONG ObjectAttributes,
    IN OUT  PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    IN      PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
    IN      PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
    IN      HANDLE ParentProcess,
    IN      BOOLEAN InheritHandles,
    IN      HANDLE DebugPort OPTIONAL,
    IN      HANDLE ExceptionPort OPTIONAL,
    OUT     PRTL_USER_PROCESS_INFORMATION ProcessInformation
) {
    NTSTATUS ret = Old_RtlCreateUserProcess(ImagePath, ObjectAttributes,
        ProcessParameters, ProcessSecurityDescriptor,
        ThreadSecurityDescriptor, ParentProcess, InheritHandles, DebugPort,
        ExceptionPort, ProcessInformation);
    LOQ("opp", "ImagePath", ImagePath, "ObjectAttributes", ObjectAttributes,
        "ParentProcess", ParentProcess);
    if(NT_SUCCESS(ret)) {
        pipe("PROCESS:%d,%d",
            pid_from_process_handle(ProcessInformation->ProcessHandle),
            pid_from_thread_handle(ProcessInformation->ThreadHandle));
        disable_sleep_skip();
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenProcess,
    __out     PHANDLE ProcessHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PCLIENT_ID ClientId
) {
    // although the documentation on msdn is a bit vague, this seems correct
    // for both XP and Vista (the ClientId->UniqueProcess part, that is)

    int pid = 0;
    if(ClientId != NULL) {
        pid = (int) ClientId->UniqueProcess;
    }

    if(is_protected_pid(pid)) {
        NTSTATUS ret = STATUS_ACCESS_DENIED;
        LOQ("ppp", "ProcessHandle", NULL, "DesiredAccess", DesiredAccess,
            "ProcessIdentifier", &pid);
        return STATUS_ACCESS_DENIED;
    }

    NTSTATUS ret = Old_NtOpenProcess(ProcessHandle, DesiredAccess,
        ObjectAttributes, ClientId);
    LOQ2("PpP", "ProcessHandle", ProcessHandle,
        "DesiredAccess", DesiredAccess,
        "ProcessIdentifier", &pid);
    /*
    if(NT_SUCCESS(ret)) {
        // let's do an extra check here, because the msdn documentation is
        // so vague..
        unsigned long pid = pid_from_process_handle(*ProcessHandle);
        // check if this pid is protected
        if(is_protected_pid(pid)) {
            CloseHandle(*ProcessHandle);
            return STATUS_ACCESS_DENIED;
        }
        pipe("PROCESS:%d", pid);
    }
    */
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtTerminateProcess,
    __in_opt  HANDLE ProcessHandle,
    __in      NTSTATUS ExitStatus
) {
    NTSTATUS ret = Old_NtTerminateProcess(ProcessHandle, ExitStatus);
    LOQ("pl", "ProcessHandle", ProcessHandle, "ExitCode", ExitStatus);
    log_flush();
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateSection,
    __out     PHANDLE SectionHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PLARGE_INTEGER MaximumSize,
    __in      ULONG SectionPageProtection,
    __in      ULONG AllocationAttributes,
    __in_opt  HANDLE FileHandle
) {
    NTSTATUS ret = Old_NtCreateSection(SectionHandle, DesiredAccess,
        ObjectAttributes, MaximumSize, SectionPageProtection,
        AllocationAttributes, FileHandle);
    LOQ("PpOp", "SectionHandle", SectionHandle,
        "DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes,
        "FileHandle", FileHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMakeTemporaryObject,
    __in     HANDLE ObjectHandle
) {
    NTSTATUS ret = Old_NtMakeTemporaryObject(ObjectHandle);
    LOQ("p", "ObjectHandle", ObjectHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtMakePermanentObject,
    __in     HANDLE ObjectHandle
) {
    NTSTATUS ret = Old_NtMakePermanentObject(ObjectHandle);
    LOQ("p", "ObjectHandle", ObjectHandle);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenSection,
    __out  PHANDLE SectionHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS ret = Old_NtOpenSection(SectionHandle, DesiredAccess,
        ObjectAttributes);
    LOQ("PpO", "SectionHandle", SectionHandle, "DesiredAccess", DesiredAccess,
        "ObjectAttributes", ObjectAttributes);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CreateProcessInternalW,
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
    BOOL ret = Old_CreateProcessInternalW(lpUnknown1, lpApplicationName,
        lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation, lpUnknown2);
    LOQ("uupllpp", "ApplicationName", lpApplicationName,
        "CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
        "ProcessId", lpProcessInformation->dwProcessId,
        "ThreadId", lpProcessInformation->dwThreadId,
        "ProcessHandle", lpProcessInformation->hProcess,
        "ThreadHandle", lpProcessInformation->hThread);
    return ret;
}

HOOKDEF(VOID, WINAPI, ExitProcess,
    __in  UINT uExitCode
) {
    IS_SUCCESS_VOID();

    int ret = 0;
    LOQ("l", "ExitCode", uExitCode);
    log_free();
    Old_ExitProcess(uExitCode);
}

HOOKDEF(BOOL, WINAPI, ShellExecuteExW,
    __inout  SHELLEXECUTEINFOW *pExecInfo
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_ShellExecuteExW(pExecInfo);
    LOQ("2ul", "FilePath", pExecInfo->lpFile,
        "Parameters", pExecInfo->lpParameters, "Show", pExecInfo->nShow);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtUnmapViewOfSection,
    _In_      HANDLE ProcessHandle,
    _In_opt_  PVOID BaseAddress
) {
    unsigned int map_size = 0; MEMORY_BASIC_INFORMATION mbi;
    if(VirtualQueryEx(ProcessHandle, BaseAddress, &mbi,
            sizeof(mbi)) == sizeof(mbi)) {
        map_size = mbi.RegionSize;
    }
    NTSTATUS ret = Old_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
    if(NT_SUCCESS(ret)) {
        pipe("UNMAP:%d,%x,%x", pid_from_process_handle(ProcessHandle),
            BaseAddress, map_size);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtAllocateVirtualMemory,
    __in     HANDLE ProcessHandle,
    __inout  PVOID *BaseAddress,
    __in     ULONG_PTR ZeroBits,
    __inout  PSIZE_T RegionSize,
    __in     ULONG AllocationType,
    __in     ULONG Protect
) {
    NTSTATUS ret = Old_NtAllocateVirtualMemory(ProcessHandle, BaseAddress,
        ZeroBits, RegionSize, AllocationType, Protect);
    LOQ("pPPp", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "RegionSize", RegionSize, "Protection", Protect);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReadVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPCVOID BaseAddress,
    __out       LPVOID Buffer,
    __in        ULONG NumberOfBytesToRead,
    __out_opt   PULONG NumberOfBytesReaded
) {
    ENSURE_ULONG(NumberOfBytesReaded);

    BOOL ret = Old_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToRead, NumberOfBytesReaded);

    LOQ("2pB", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "Buffer", NumberOfBytesReaded, Buffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, ReadProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPCVOID lpBaseAddress,
    _Out_   LPVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   SIZE_T *lpNumberOfBytesRead
) {
    IS_SUCCESS_BOOL();
    ENSURE_SIZET(lpNumberOfBytesRead);

    BOOL ret = Old_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer,
        nSize, lpNumberOfBytesRead);

    LOQ("ppB", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress,
        "Buffer", lpNumberOfBytesRead, lpBuffer);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWriteVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPVOID BaseAddress,
    __in        LPCVOID Buffer,
    __in        ULONG NumberOfBytesToWrite,
    __out_opt   ULONG *NumberOfBytesWritten
) {
    ENSURE_ULONG(NumberOfBytesWritten);

    BOOL ret = Old_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToWrite, NumberOfBytesWritten);

    LOQ("2pB", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "Buffer", NumberOfBytesWritten, Buffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, WriteProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPVOID lpBaseAddress,
    _In_    LPCVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   SIZE_T *lpNumberOfBytesWritten
) {
    IS_SUCCESS_BOOL();
    ENSURE_SIZET(lpNumberOfBytesWritten);

    BOOL ret = Old_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer,
        nSize, lpNumberOfBytesWritten);

    LOQ("ppB", "ProcessHandle", hProcess, "BaseAddress", lpBaseAddress,
        "Buffer", lpNumberOfBytesWritten, lpBuffer);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtProtectVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN OUT  PVOID *BaseAddress,
    IN OUT  PULONG NumberOfBytesToProtect,
    IN      ULONG NewAccessProtection,
    OUT     PULONG OldAccessProtection
) {
    NTSTATUS ret = Old_NtProtectVirtualMemory(ProcessHandle, BaseAddress,
        NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
    LOQ("pPPpP", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "NumberOfBytesProtected", NumberOfBytesToProtect,
        "NewAccessProtection", NewAccessProtection,
        "OldAccessProtection", OldAccessProtection);
    return ret;
}

HOOKDEF(BOOL, WINAPI, VirtualProtectEx,
    __in   HANDLE hProcess,
    __in   LPVOID lpAddress,
    __in   SIZE_T dwSize,
    __in   DWORD flNewProtect,
    __out  PDWORD lpflOldProtect
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect,
        lpflOldProtect);
    LOQ("pppp", "ProcessHandle", hProcess, "Address", lpAddress,
        "Size", dwSize, "Protection", flNewProtect);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtFreeVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN      PVOID *BaseAddress,
    IN OUT  PULONG RegionSize,
    IN      ULONG FreeType
) {
    NTSTATUS ret = Old_NtFreeVirtualMemory(ProcessHandle, BaseAddress,
        RegionSize, FreeType);
    LOQ("pPPp", "ProcessHandle", ProcessHandle, "BaseAddress", BaseAddress,
        "RegionSize", RegionSize, "FreeType", FreeType);
    return ret;
}

HOOKDEF(BOOL, WINAPI, VirtualFreeEx,
    __in  HANDLE hProcess,
    __in  LPVOID lpAddress,
    __in  SIZE_T dwSize,
    __in  DWORD dwFreeType
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);
    LOQ("pppl", "ProcessHandle", hProcess, "Address", lpAddress,
        "Size", dwSize, "FreeType", dwFreeType);
    return ret;
}

HOOKDEF(int, CDECL, system,
    const char *command
) {
    IS_SUCCESS_INTM1();

    int ret = Old_system(command);
    LOQ("s", "Command", command);
    return ret;
}
