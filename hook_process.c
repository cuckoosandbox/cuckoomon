#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"

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
    LOQ("PO", "ProcessHandle", ProcessHandle, "FileName", ObjectAttributes);
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
    LOQ("PO", "ProcessHandle", ProcessHandle, "FileName", ObjectAttributes);
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
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation, lpUnknown2);
    LOQ("uu3l2p", "ApplicationName", lpApplicationName,
        "CommandLine", lpCommandLine, "CreationFlags", dwCreationFlags,
        "ProcessId", lpProcessInformation->dwProcessId,
        "ThreadId", lpProcessInformation->dwThreadId,
        "ProcessHandle", lpProcessInformation->hProcess,
        "ThreadHandle", lpProcessInformation->hThread);
    return ret;
}

HOOKDEF(HANDLE, WINAPI, OpenProcess,
  __in  DWORD dwDesiredAccess,
  __in  BOOL bInheritHandle,
  __in  DWORD dwProcessId
) {
    HANDLE ret = Old_OpenProcess(dwDesiredAccess, bInheritHandle,
        dwProcessId);
    LOQ("ll", "DesiredAccess", dwDesiredAccess, "ProcessId", dwProcessId);
    return ret;
}

HOOKDEF(BOOL, WINAPI, TerminateProcess,
  __in  HANDLE hProcess,
  __in  UINT uExitCode
) {
    BOOL ret = Old_TerminateProcess(hProcess, uExitCode);
    LOQ("pl", "ProcessHandle", hProcess, "ExitCode", uExitCode);
    return ret;
}

HOOKDEF(VOID, WINAPI, ExitProcess,
  __in  UINT uExitCode
) {
    int ret = 0;
    LOQ("l", "ExitCode", uExitCode);
    Old_ExitProcess(uExitCode);
}

HOOKDEF(BOOL, WINAPI, ShellExecuteExW,
  __inout  SHELLEXECUTEINFOW *pExecInfo
) {
    BOOL ret = Old_ShellExecuteExW(pExecInfo);
    LOQ("2ul", pExecInfo->lpFile, pExecInfo->lpParameters, pExecInfo->nShow);
    return ret;
}
