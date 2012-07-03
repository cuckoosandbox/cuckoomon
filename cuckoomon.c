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
#include "ntapi.h"
#include "hooking.h"
#include "hooks.h"

#define HOOK(library, funcname) {#library, #funcname, NULL, &New_##funcname, \
    (void **) &Old_##funcname}

static hook_t g_hooks[] = {

    //
    // File Hooks
    //

    HOOK(ntdll, NtCreateFile),
    HOOK(ntdll, NtOpenFile),
    HOOK(ntdll, NtReadFile),
    HOOK(ntdll, NtWriteFile),

    // lowest variant of MoveFile()
    HOOK(kernel32, MoveFileWithProgressW),

    // perhaps go for NtSetInformationFile() later
    HOOK(kernel32, DeleteFileW),

    //
    // Registry Hooks
    //
    // Note: Most, if not all, of the Registry API go natively from both the
    // A as well as the W versions. In other words, we have to hook all the
    // ascii *and* unicode APIs of those functions.
    //

    HOOK(advapi32, RegOpenKeyExA),
    HOOK(advapi32, RegOpenKeyExW),

    HOOK(advapi32, RegCreateKeyExA),
    HOOK(advapi32, RegCreateKeyExW),

    // Note that RegDeleteKeyEx() is available for 64bit XP/Vista+
    HOOK(advapi32, RegDeleteKeyA),
    HOOK(advapi32, RegDeleteKeyW),

    // RegEnumKeyA() calls RegEnumKeyExA(), but RegEnumKeyW() does *not*
    // call RegEnumKeyExW()
    HOOK(advapi32, RegEnumKeyW),
    HOOK(advapi32, RegEnumKeyExA),
    HOOK(advapi32, RegEnumKeyExW),

    HOOK(advapi32, RegEnumValueA),
    HOOK(advapi32, RegEnumValueW),

    HOOK(advapi32, RegSetValueExA),
    HOOK(advapi32, RegSetValueExW),

    HOOK(advapi32, RegQueryValueExA),
    HOOK(advapi32, RegQueryValueExW),

    HOOK(advapi32, RegDeleteValueA),
    HOOK(advapi32, RegDeleteValueW),

    //
    // Window Hooks
    //

    HOOK(user32, FindWindowA),
    HOOK(user32, FindWindowW),
    HOOK(user32, FindWindowExA),
    HOOK(user32, FindWindowExW),

    //
    // Sync Hooks
    //

    HOOK(ntdll, NtCreateMutant),
    HOOK(ntdll, NtOpenMutant),

    //
    // Process Hooks
    //

    HOOK(ntdll, NtCreateProcess),
    HOOK(ntdll, NtCreateProcessEx),
    HOOK(kernel32, CreateProcessInternalW),
    HOOK(kernel32, OpenProcess),
    HOOK(kernel32, TerminateProcess),
    HOOK(kernel32, ExitProcess),

    // all variants of ShellExecute end up in ShellExecuteExW
    HOOK(shell32, ShellExecuteExW),
    HOOK(kernel32, ReadProcessMemory),
    HOOK(kernel32, WriteProcessMemory),
    HOOK(kernel32, VirtualAllocEx),
    HOOK(kernel32, VirtualProtectEx),

    //
    // Thread Hooks
    //

    HOOK(kernel32, OpenThread),
    HOOK(kernel32, CreateRemoteThread),
    HOOK(kernel32, TerminateThread),
    HOOK(kernel32, ExitThread),
    HOOK(kernel32, GetThreadContext),
    HOOK(kernel32, SetThreadContext),
    HOOK(kernel32, SuspendThread),
    HOOK(kernel32, ResumeThread),

    //
    // Misc Hooks
    //

    HOOK(user32, SetWindowsHookExA),
    HOOK(user32, SetWindowsHookExW),
    HOOK(ntdll, LdrLoadDll),
    HOOK(ntdll, LdrGetDllHandle),
    HOOK(ntdll, LdrGetProcedureAddress),
    HOOK(kernel32, DeviceIoControl),
    HOOK(ntdll, NtDelayExecution),
    HOOK(user32, ExitWindowsEx),
    HOOK(kernel32, IsDebuggerPresent),
    HOOK(advapi32, LookupPrivilegeValueW),

    //
    // Network Hooks
    //

    HOOK(urlmon, URLDownloadToFileW),
    HOOK(wininet, InternetOpenUrlA),
    HOOK(wininet, InternetOpenUrlW),
    HOOK(wininet, HttpOpenRequestA),
    HOOK(wininet, HttpOpenRequestW),
    HOOK(wininet, HttpSendRequestA),
    HOOK(wininet, HttpSendRequestW),

    //
    // Service Hooks
    //

    HOOK(advapi32, OpenSCManagerA),
    HOOK(advapi32, OpenSCManagerW),
    HOOK(advapi32, CreateServiceA),
    HOOK(advapi32, CreateServiceW),
    HOOK(advapi32, OpenServiceA),
    HOOK(advapi32, OpenServiceW),
    HOOK(advapi32, StartServiceA),
    HOOK(advapi32, StartServiceW),
    HOOK(advapi32, ControlService),
    HOOK(advapi32, DeleteService),
};

void set_hooks()
{
    // the hooks contain the gates as well, so they have to be RWX
    DWORD old_protect;
    VirtualProtect(g_hooks, sizeof(g_hooks), PAGE_EXECUTE_READWRITE,
        &old_protect);

    hook_disable();

    // now, hook each api :)
    for (int i = 0; i < ARRAYSIZE(g_hooks); i++) {
        hook_api(&g_hooks[i], HOOK_DIRECT_JMP);
    }

    hook_enable();
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if(dwReason == DLL_PROCESS_ATTACH) {
        set_hooks();
    }
    return TRUE;
}
