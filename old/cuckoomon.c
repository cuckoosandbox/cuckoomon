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
#include "ntapi.h"
#include "misc.h"
#include "hooking.h"
#include "hooks.h"
#include "log.h"
#include "pipe.h"
#include "ignore.h"
#include "hook_file.h"
#include "hook_sleep.h"
#include "config.h"

#define HOOK(library, funcname) {L###library, #funcname, NULL, \
    &New_##funcname, (void **) &Old_##funcname}

#define HOOK2(library, funcname, recursion) {L###library, #funcname, NULL, \
    &New2_##funcname, (void **) &Old2_##funcname, recursion}

static hook_t g_hooks[] = {

    //
    // Special Hooks
    //
    // NOTE: due to the fact that the "special" hooks don't use a hook count
    // (whereas the "normal" hooks, those with allow_hook_recursion set to
    // zero, do) we have to hook the "special" hooks first. Otherwise the
    // execution flow will end up in an infinite loop, because of hook count
    // and whatnot.
    //
    // In other words, do *NOT* place "special" hooks behind "normal" hooks.
    //

    HOOK2(ntdll, LdrLoadDll, TRUE),
    HOOK2(kernel32, CreateProcessInternalW, TRUE),

    //
    // File Hooks
    //

    HOOK(ntdll, NtCreateFile),
    HOOK(ntdll, NtOpenFile),
    HOOK(ntdll, NtReadFile),
    HOOK(ntdll, NtWriteFile),
    HOOK(ntdll, NtDeleteFile),
    HOOK(ntdll, NtDeviceIoControlFile),
    HOOK(ntdll, NtQueryDirectoryFile),
    HOOK(ntdll, NtQueryInformationFile),
    HOOK(ntdll, NtSetInformationFile),
    HOOK(ntdll, NtOpenDirectoryObject),
    HOOK(ntdll, NtCreateDirectoryObject),

    // CreateDirectoryExA calls CreateDirectoryExW
    // CreateDirectoryW does not call CreateDirectoryExW
    HOOK(kernel32, CreateDirectoryW),
    HOOK(kernel32, CreateDirectoryExW),

    HOOK(kernel32, RemoveDirectoryA),
    HOOK(kernel32, RemoveDirectoryW),

    // lowest variant of MoveFile()
    HOOK(kernel32, MoveFileWithProgressW),

    HOOK(kernel32, FindFirstFileExA),
    HOOK(kernel32, FindFirstFileExW),

    // Covered by NtCreateFile() but still grap this information
    HOOK(kernel32, CopyFileA),
    HOOK(kernel32, CopyFileW),
    HOOK(kernel32, CopyFileExW),

    // Covered by NtSetInformationFile() but still grap this information
    HOOK(kernel32, DeleteFileA),
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

    HOOK(advapi32, RegQueryInfoKeyA),
    HOOK(advapi32, RegQueryInfoKeyW),

    HOOK(advapi32, RegCloseKey),

    //
    // Native Registry Hooks
    //

    HOOK(ntdll, NtCreateKey),
    HOOK(ntdll, NtOpenKey),
    HOOK(ntdll, NtOpenKeyEx),
    HOOK(ntdll, NtRenameKey),
    HOOK(ntdll, NtReplaceKey),
    HOOK(ntdll, NtEnumerateKey),
    HOOK(ntdll, NtEnumerateValueKey),
    HOOK(ntdll, NtSetValueKey),
    HOOK(ntdll, NtQueryValueKey),
    HOOK(ntdll, NtQueryMultipleValueKey),
    HOOK(ntdll, NtDeleteKey),
    HOOK(ntdll, NtDeleteValueKey),
    HOOK(ntdll, NtLoadKey),
    HOOK(ntdll, NtLoadKey2),
    HOOK(ntdll, NtLoadKeyEx),
    HOOK(ntdll, NtQueryKey),
    HOOK(ntdll, NtSaveKey),
    HOOK(ntdll, NtSaveKeyEx),

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
    HOOK(ntdll, NtCreateNamedPipeFile),

    //
    // Process Hooks
    //

    HOOK(ntdll, NtCreateProcess),
    HOOK(ntdll, NtCreateProcessEx),
    HOOK(ntdll, NtCreateUserProcess),
    HOOK(ntdll, RtlCreateUserProcess),
    //HOOK(ntdll, NtOpenProcess),
    HOOK(ntdll, NtTerminateProcess),
    HOOK(ntdll, NtCreateSection),
    HOOK(ntdll, NtMakeTemporaryObject),
    HOOK(ntdll, NtMakePermanentObject),
    HOOK(ntdll, NtOpenSection),
    //HOOK(kernel32, CreateProcessInternalW),
    HOOK(ntdll, ZwMapViewOfSection),
    HOOK(kernel32, ExitProcess),

    // all variants of ShellExecute end up in ShellExecuteExW
    HOOK(shell32, ShellExecuteExW),
    HOOK(ntdll, NtUnmapViewOfSection),
    // HOOK(ntdll, NtAllocateVirtualMemory),
    HOOK(ntdll, NtReadVirtualMemory),
    HOOK(kernel32, ReadProcessMemory),
    HOOK(ntdll, NtWriteVirtualMemory),
    HOOK(kernel32, WriteProcessMemory),
    HOOK(ntdll, NtProtectVirtualMemory),
    HOOK(kernel32, VirtualProtectEx),
    HOOK(ntdll, NtFreeVirtualMemory),
    //HOOK(kernel32, VirtualFreeEx),

    HOOK(msvcrt, system),

    //
    // Thread Hooks
    //

    HOOK(ntdll, NtCreateThread),
    HOOK(ntdll, NtCreateThreadEx),
    HOOK(ntdll, NtOpenThread),
    HOOK(ntdll, NtGetContextThread),
    HOOK(ntdll, NtSetContextThread),
    HOOK(ntdll, NtSuspendThread),
    HOOK(ntdll, NtResumeThread),
    HOOK(ntdll, NtTerminateThread),
    HOOK(kernel32, CreateThread),
    HOOK(kernel32, CreateRemoteThread),
    HOOK(kernel32, ExitThread),
    HOOK(ntdll, RtlCreateUserThread),

    //
    // Misc Hooks
    //

    HOOK(user32, SetWindowsHookExA),
    HOOK(user32, SetWindowsHookExW),
    HOOK(user32, UnhookWindowsHookEx),
    //HOOK(ntdll, LdrLoadDll),
    HOOK(ntdll, LdrGetDllHandle),
    HOOK(ntdll, LdrGetProcedureAddress),
    HOOK(kernel32, DeviceIoControl),
    HOOK(user32, ExitWindowsEx),
    HOOK(kernel32, IsDebuggerPresent),
    HOOK(advapi32, LookupPrivilegeValueW),
    //HOOK(ntdll, NtClose),
    HOOK(kernel32, WriteConsoleA),
    HOOK(kernel32, WriteConsoleW),
    HOOK(user32, GetSystemMetrics),
    HOOK(user32, GetCursorPos),

    //
    // Network Hooks
    //

    HOOK(urlmon, URLDownloadToFileW),
    HOOK(wininet, InternetOpenA),
    HOOK(wininet, InternetOpenW),
    HOOK(wininet, InternetConnectA),
    HOOK(wininet, InternetConnectW),
    HOOK(wininet, InternetOpenUrlA),
    HOOK(wininet, InternetOpenUrlW),
    HOOK(wininet, HttpOpenRequestA),
    HOOK(wininet, HttpOpenRequestW),
    HOOK(wininet, HttpSendRequestA),
    HOOK(wininet, HttpSendRequestW),
    HOOK(wininet, InternetReadFile),
    HOOK(wininet, InternetWriteFile),
    HOOK(wininet, InternetCloseHandle),

    HOOK(dnsapi, DnsQuery_A),
    HOOK(dnsapi, DnsQuery_UTF8),
    HOOK(dnsapi, DnsQuery_W),
    HOOK(ws2_32, getaddrinfo),
    HOOK(ws2_32, GetAddrInfoW),

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

    //
    // Sleep Hooks
    //

    HOOK(ntdll, NtDelayExecution),
    HOOK(kernel32, GetLocalTime),
    HOOK(kernel32, GetSystemTime),
    HOOK(kernel32, GetTickCount),
    HOOK(ntdll, NtQuerySystemTime),

    //
    // Socket Hooks
    //

    HOOK(ws2_32, WSAStartup),
    HOOK(ws2_32, gethostbyname),
    HOOK(ws2_32, socket),
    HOOK(ws2_32, connect),
    HOOK(ws2_32, send),
    HOOK(ws2_32, sendto),
    HOOK(ws2_32, recv),
    HOOK(ws2_32, recvfrom),
    HOOK(ws2_32, accept),
    HOOK(ws2_32, bind),
    HOOK(ws2_32, listen),
    HOOK(ws2_32, select),
    HOOK(ws2_32, setsockopt),
    HOOK(ws2_32, ioctlsocket),
    HOOK(ws2_32, closesocket),
    HOOK(ws2_32, shutdown),

    HOOK(ws2_32, WSARecv),
    HOOK(ws2_32, WSARecvFrom),
    HOOK(ws2_32, WSASend),
    HOOK(ws2_32, WSASendTo),
    HOOK(ws2_32, WSASocketA),
    HOOK(ws2_32, WSASocketW),

    // HOOK(wsock32, connect),
    // HOOK(wsock32, send),
    // HOOK(wsock32, recv),

    HOOK(mswsock, ConnectEx),
    HOOK(mswsock, TransmitFile),
};

// get a random hooking method, except for hook_jmp_direct
//#define HOOKTYPE randint(HOOK_NOP_JMP_DIRECT, HOOK_MOV_EAX_INDIRECT_PUSH_RETN)
// error testing with hook_jmp_direct only
#define HOOKTYPE HOOK_JMP_DIRECT

void set_hooks_dll(const wchar_t *library, int len)
{
    for (int i = 0; i < ARRAYSIZE(g_hooks); i++) {
        if(!wcsnicmp(g_hooks[i].library, library, len)) {
            hook_api(&g_hooks[i], HOOKTYPE);
        }
    }
}

void set_hooks()
{
    // the hooks contain executable code as well, so they have to be RWX
    DWORD old_protect;
    VirtualProtect(g_hooks, sizeof(g_hooks), PAGE_EXECUTE_READWRITE,
        &old_protect);

    hook_disable();

    // now, hook each api :)
    for (int i = 0; i < ARRAYSIZE(g_hooks); i++) {
        if(g_hooks[i].allow_hook_recursion != FALSE) {
            hook_api(&g_hooks[i], HOOKTYPE);
        }
        else {
            hook_api(&g_hooks[i], HOOKTYPE);
        }
    }

    hook_enable();
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if(dwReason == DLL_PROCESS_ATTACH) {
        // make sure advapi32 is loaded
        LoadLibrary("advapi32");

        // there's a small list of processes which we don't want to inject
        if(is_ignored_process()) {
            return TRUE;
        }

        // hide our module from peb
        hide_module_from_peb(hModule);

        // obtain all protected pids
        int pids[MAX_PROTECTED_PIDS], length = sizeof(pids);
        pipe2(pids, &length, "GETPIDS");
        for (int i = 0; i < length / sizeof(pids[0]); i++) {
            add_protected_pid(pids[i]);
        }

        // initialize file stuff
        file_init();

        // read the config settings
        read_config();
        g_pipe_name = g_config.pipe_name;

        // initialize the log file
        log_init(g_config.host_ip, g_config.host_port, 0);

        // initialize the Sleep() skipping stuff
        init_sleep_skip(g_config.first_process);

        // we skip a random given amount of milliseconds each run
        init_startup_time(g_config.startup_time);

        // disable the retaddr check if the user wants so
        if(g_config.retaddr_check == 0) {
            hook_disable_retaddr_check();
        }

        // initialize all hooks
        set_hooks();

        // notify analyzer.py that we've loaded
        char name[64];
        sprintf(name, "CuckooEvent%d", GetCurrentProcessId());
        HANDLE event_handle = OpenEvent(EVENT_ALL_ACCESS, FALSE, name);
        if(event_handle != NULL) {
            SetEvent(event_handle);
            CloseHandle(event_handle);
        }
    }
    else if(dwReason == DLL_PROCESS_DETACH) {
        log_free();
    }

    return TRUE;
}
