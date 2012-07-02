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

HOOKDEF(HANDLE, WINAPI, OpenThread,
  __in  DWORD dwDesiredAccess,
  __in  BOOL bInheritHandle,
  __in  DWORD dwThreadId
) {
    HANDLE ret = Old_OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    LOQ("ll", "DesiredAccess", dwDesiredAccess, "ThreadId", dwThreadId);
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
    BOOL ret = Old_TerminateThread(hThread, dwExitCode);
    LOQ("pl", "ThreadHandle", hThread, "ExitCode", dwExitCode);
    return ret;
}

HOOKDEF(VOID, WINAPI, ExitThread,
  __in  DWORD dwExitCode
) {
    int ret = 0;
    LOQ("l", "ExitCode", dwExitCode);
    Old_ExitThread(dwExitCode);
}

HOOKDEF(BOOL, WINAPI, GetThreadContext,
  __in     HANDLE hThread,
  __inout  LPCONTEXT lpContext
) {
    BOOL ret = Old_GetThreadContext(hThread, lpContext);
    LOQ("p", "ThreadHandle", hThread);
    return ret;
}

HOOKDEF(BOOL, WINAPI, SetThreadContext,
  __in  HANDLE hThread,
  __in  const CONTEXT *lpContext
) {
    BOOL ret = Old_SetThreadContext(hThread, lpContext);
    LOQ("p", "ThreadHandle", hThread);
    return ret;
}

HOOKDEF(DWORD, WINAPI, SuspendThread,
  __in  HANDLE hThread
) {
    DWORD ret = Old_SuspendThread(hThread);
    LOQ("p", "ThreadHandle", hThread);
    return ret;
}

HOOKDEF(DWORD, WINAPI, ResumeThread,
  __in  HANDLE hThread
) {
    DWORD ret = Old_ResumeThread(hThread);
    LOQ("p", "ThreadHandle", hThread);
    return ret;
}
