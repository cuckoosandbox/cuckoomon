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

#include <windns.h>
#include "ntapi.h"

//
// File Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateFile,
  __out     PHANDLE FileHandle,
  __in      ACCESS_MASK DesiredAccess,
  __in      POBJECT_ATTRIBUTES ObjectAttributes,
  __out     PIO_STATUS_BLOCK IoStatusBlock,
  __in_opt  PLARGE_INTEGER AllocationSize,
  __in      ULONG FileAttributes,
  __in      ULONG ShareAccess,
  __in      ULONG CreateDisposition,
  __in      ULONG CreateOptions,
  __in      PVOID EaBuffer,
  __in      ULONG EaLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenFile,
  __out  PHANDLE FileHandle,
  __in   ACCESS_MASK DesiredAccess,
  __in   POBJECT_ATTRIBUTES ObjectAttributes,
  __out  PIO_STATUS_BLOCK IoStatusBlock,
  __in   ULONG ShareAccess,
  __in   ULONG OpenOptions
);

extern HOOKDEF(NTSTATUS, WINAPI, NtReadFile,
  __in      HANDLE FileHandle,
  __in_opt  HANDLE Event,
  __in_opt  PIO_APC_ROUTINE ApcRoutine,
  __in_opt  PVOID ApcContext,
  __out     PIO_STATUS_BLOCK IoStatusBlock,
  __out     PVOID Buffer,
  __in      ULONG Length,
  __in_opt  PLARGE_INTEGER ByteOffset,
  __in_opt  PULONG Key
);

extern HOOKDEF(NTSTATUS, WINAPI, NtWriteFile,
  __in      HANDLE FileHandle,
  __in_opt  HANDLE Event,
  __in_opt  PIO_APC_ROUTINE ApcRoutine,
  __in_opt  PVOID ApcContext,
  __out     PIO_STATUS_BLOCK IoStatusBlock,
  __in      PVOID Buffer,
  __in      ULONG Length,
  __in_opt  PLARGE_INTEGER ByteOffset,
  __in_opt  PULONG Key
);

extern HOOKDEF(BOOL, WINAPI, MoveFileWithProgressW,
  __in      LPWSTR lpExistingFileName,
  __in_opt  LPWSTR lpNewFileName,
  __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
  __in_opt  LPVOID lpData,
  __in      DWORD dwFlags
);

extern HOOKDEF(BOOL, WINAPI, DeleteFileW,
  __in  LPWSTR lpFileName
);

extern HOOKDEF(BOOL, WINAPI, CreateDirectoryW,
  __in      LPCTSTR lpPathName,
  __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

extern HOOKDEF(BOOL, WINAPI, CreateDirectoryExW,
  __in      LPWSTR lpTemplateDirectory,
  __in      LPWSTR lpNewDirectory,
  __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

//
// Registry Hooks
//

extern HOOKDEF(LONG, WINAPI, RegOpenKeyExA,
  __in        HKEY hKey,
  __in_opt    LPCTSTR lpSubKey,
  __reserved  DWORD ulOptions,
  __in        REGSAM samDesired,
  __out       PHKEY phkResult
);

extern HOOKDEF(LONG, WINAPI, RegOpenKeyExW,
  __in        HKEY hKey,
  __in_opt    LPWSTR lpSubKey,
  __reserved  DWORD ulOptions,
  __in        REGSAM samDesired,
  __out       PHKEY phkResult
);

extern HOOKDEF(LONG, WINAPI, RegCreateKeyExA,
  __in        HKEY hKey,
  __in        LPCTSTR lpSubKey,
  __reserved  DWORD Reserved,
  __in_opt    LPTSTR lpClass,
  __in        DWORD dwOptions,
  __in        REGSAM samDesired,
  __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __out       PHKEY phkResult,
  __out_opt   LPDWORD lpdwDisposition
);

extern HOOKDEF(LONG, WINAPI, RegCreateKeyExW,
  __in        HKEY hKey,
  __in        LPWSTR lpSubKey,
  __reserved  DWORD Reserved,
  __in_opt    LPWSTR lpClass,
  __in        DWORD dwOptions,
  __in        REGSAM samDesired,
  __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __out       PHKEY phkResult,
  __out_opt   LPDWORD lpdwDisposition
);

extern HOOKDEF(LONG, WINAPI, RegDeleteKeyA,
  __in  HKEY hKey,
  __in  LPCTSTR lpSubKey
);

extern HOOKDEF(LONG, WINAPI, RegDeleteKeyW,
  __in  HKEY hKey,
  __in  LPWSTR lpSubKey
);

extern HOOKDEF(LONG, WINAPI, RegEnumKeyW,
  __in   HKEY hKey,
  __in   DWORD dwIndex,
  __out  LPWSTR lpName,
  __in   DWORD cchName
);

extern HOOKDEF(LONG, WINAPI, RegEnumKeyExA,
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPTSTR lpName,
  __inout      LPDWORD lpcName,
  __reserved   LPDWORD lpReserved,
  __inout      LPTSTR lpClass,
  __inout_opt  LPDWORD lpcClass,
  __out_opt    PFILETIME lpftLastWriteTime
);

extern HOOKDEF(LONG, WINAPI, RegEnumKeyExW,
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPWSTR lpName,
  __inout      LPDWORD lpcName,
  __reserved   LPDWORD lpReserved,
  __inout      LPWSTR lpClass,
  __inout_opt  LPDWORD lpcClass,
  __out_opt    PFILETIME lpftLastWriteTime
);

extern HOOKDEF(LONG, WINAPI, RegEnumValueA,
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPTSTR lpValueName,
  __inout      LPDWORD lpcchValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegEnumValueW,
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPWSTR lpValueName,
  __inout      LPDWORD lpcchValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegSetValueExA,
  __in        HKEY hKey,
  __in_opt    LPCTSTR lpValueName,
  __reserved  DWORD Reserved,
  __in        DWORD dwType,
  __in        const BYTE *lpData,
  __in        DWORD cbData
);

extern HOOKDEF(LONG, WINAPI, RegSetValueExW,
  __in        HKEY hKey,
  __in_opt    LPWSTR lpValueName,
  __reserved  DWORD Reserved,
  __in        DWORD dwType,
  __in        const BYTE *lpData,
  __in        DWORD cbData
);

extern HOOKDEF(LONG, WINAPI, RegQueryValueExA,
  __in         HKEY hKey,
  __in_opt     LPCTSTR lpValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegQueryValueExW,
  __in         HKEY hKey,
  __in_opt     LPWSTR lpValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

extern HOOKDEF(LONG, WINAPI, RegDeleteValueA,
  __in      HKEY hKey,
  __in_opt  LPCTSTR lpValueName
);

extern HOOKDEF(LONG, WINAPI, RegDeleteValueW,
  __in      HKEY hKey,
  __in_opt  LPWSTR lpValueName
);

extern HOOKDEF(LONG, WINAPI, RegCloseKey,
    __in    HKEY hKey
);

//
// Window Hooks
//

extern HOOKDEF(HWND, WINAPI, FindWindowA,
  __in_opt  LPCTSTR lpClassName,
  __in_opt  LPCTSTR lpWindowName
);

extern HOOKDEF(HWND, WINAPI, FindWindowW,
  __in_opt  LPWSTR lpClassName,
  __in_opt  LPWSTR lpWindowName
);

extern HOOKDEF(HWND, WINAPI, FindWindowExA,
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPCTSTR lpszClass,
  __in_opt  LPCTSTR lpszWindow
);

extern HOOKDEF(HWND, WINAPI, FindWindowExW,
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPWSTR lpszClass,
  __in_opt  LPWSTR lpszWindow
);

//
// Sync Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateMutant,
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        BOOLEAN InitialOwner
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenMutant,
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in        POBJECT_ATTRIBUTES ObjectAttributes
);

//
// Process Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateProcess,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        BOOLEAN InheritObjectTable,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateProcessEx,
    __out       PHANDLE ProcessHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        HANDLE ParentProcess,
    __in        ULONG Flags,
    __in_opt    HANDLE SectionHandle,
    __in_opt    HANDLE DebugPort,
    __in_opt    HANDLE ExceptionPort,
    __in        BOOLEAN InJob
);

extern HOOKDEF(BOOL, WINAPI, CreateProcessInternalW,
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
);

extern HOOKDEF(HANDLE, WINAPI, OpenProcess,
  __in  DWORD dwDesiredAccess,
  __in  BOOL bInheritHandle,
  __in  DWORD dwProcessId
);

extern HOOKDEF(BOOL, WINAPI, TerminateProcess,
  __in  HANDLE hProcess,
  __in  UINT uExitCode
);

extern HOOKDEF(VOID, WINAPI, ExitProcess,
  __in  UINT uExitCode
);

extern HOOKDEF(BOOL, WINAPI, ShellExecuteExW,
  __inout  SHELLEXECUTEINFOW *pExecInfo
);

extern HOOKDEF(NTSTATUS, WINAPI, NtReadVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPCVOID BaseAddress,
    __out       LPVOID Buffer,
    __in        ULONG NumberOfBytesToRead,
    __out_opt   PULONG NumberOfBytesReaded
);

extern HOOKDEF(NTSTATUS, WINAPI, NtWriteVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPVOID BaseAddress,
    __in        LPCVOID Buffer,
    __in        ULONG NumberOfBytesToWrite,
    __out_opt   ULONG *NumberOfBytesWritten
);

extern HOOKDEF(LPVOID, WINAPI, VirtualAllocEx,
    __in      HANDLE hProcess,
    __in_opt  LPVOID lpAddress,
    __in      SIZE_T dwSize,
    __in      DWORD flAllocationType,
    __in      DWORD flProtect
);

extern HOOKDEF(BOOL, WINAPI, VirtualProtectEx,
    __in   HANDLE hProcess,
    __in   LPVOID lpAddress,
    __in   SIZE_T dwSize,
    __in   DWORD flNewProtect,
    __out  PDWORD lpflOldProtect
);

extern HOOKDEF(BOOL, WINAPI, VirtualFreeEx,
    __in  HANDLE hProcess,
    __in  LPVOID lpAddress,
    __in  SIZE_T dwSize,
    __in  DWORD dwFreeType
);

//
// Thread Hooks
//

extern HOOKDEF(HANDLE, WINAPI, OpenThread,
  __in  DWORD dwDesiredAccess,
  __in  BOOL bInheritHandle,
  __in  DWORD dwThreadId
);

extern HOOKDEF(HANDLE, WINAPI, CreateThread,
  __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
  __in   SIZE_T dwStackSize,
  __in   LPTHREAD_START_ROUTINE lpStartAddress,
  __in   LPVOID lpParameter,
  __in   DWORD dwCreationFlags,
  __out  LPDWORD lpThreadId
);

extern HOOKDEF(HANDLE, WINAPI, CreateRemoteThread,
  __in   HANDLE hProcess,
  __in   LPSECURITY_ATTRIBUTES lpThreadAttributes,
  __in   SIZE_T dwStackSize,
  __in   LPTHREAD_START_ROUTINE lpStartAddress,
  __in   LPVOID lpParameter,
  __in   DWORD dwCreationFlags,
  __out  LPDWORD lpThreadId
);

extern HOOKDEF(BOOL, WINAPI, TerminateThread,
  __inout  HANDLE hThread,
  __in     DWORD dwExitCode
);

extern HOOKDEF(VOID, WINAPI, ExitThread,
  __in  DWORD dwExitCode
);

extern HOOKDEF(NTSTATUS, WINAPI, NtGetContextThread,
  __in     HANDLE ThreadHandle,
  __inout  LPCONTEXT Context
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSetContextThread,
  __in  HANDLE ThreadHandle,
  __in  const CONTEXT *Context
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSuspendThread,
  __in          HANDLE ThreadHandle,
  __out_opt     ULONG *PreviousSuspendCount
);

extern HOOKDEF(NTSTATUS, WINAPI, NtResumeThread,
  __in          HANDLE ThreadHandle,
  __out_opt     ULONG *SuspendCount
);

//
// Misc Hooks
//

extern HOOKDEF(HHOOK, WINAPI, SetWindowsHookExA,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
);

extern HOOKDEF(HHOOK, WINAPI, SetWindowsHookExW,
    __in  int idHook,
    __in  HOOKPROC lpfn,
    __in  HINSTANCE hMod,
    __in  DWORD dwThreadId
);

extern HOOKDEF(BOOL, WINAPI, UnhookWindowsHookEx,
  __in  HHOOK hhk
);

extern HOOKDEF(NTSTATUS, WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    ULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, LdrGetDllHandle,
    __in_opt    PWORD pwPath,
    __in_opt    PVOID Unused,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE pHModule
);

extern HOOKDEF(NTSTATUS, WINAPI, LdrGetProcedureAddress,
    __in        HMODULE ModuleHandle,
    __in_opt    PANSI_STRING FunctionName,
    __in_opt    WORD Ordinal,
    __out       PVOID *FunctionAddress
);

extern HOOKDEF(BOOL, WINAPI, DeviceIoControl,
  __in         HANDLE hDevice,
  __in         DWORD dwIoControlCode,
  __in_opt     LPVOID lpInBuffer,
  __in         DWORD nInBufferSize,
  __out_opt    LPVOID lpOutBuffer,
  __in         DWORD nOutBufferSize,
  __out_opt    LPDWORD lpBytesReturned,
  __inout_opt  LPOVERLAPPED lpOverlapped
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDelayExecution,
    __in    BOOLEAN Alertable,
    __in    PLARGE_INTEGER DelayInterval
);

extern HOOKDEF(BOOL, WINAPI, ExitWindowsEx,
  __in  UINT uFlags,
  __in  DWORD dwReason
);

extern HOOKDEF(BOOL, WINAPI, IsDebuggerPresent,
    void
);

extern HOOKDEF(BOOL, WINAPI, LookupPrivilegeValueW,
  __in_opt  LPWSTR lpSystemName,
  __in      LPWSTR lpName,
  __out     PLUID lpLuid
);

extern HOOKDEF(NTSTATUS, WINAPI, NtClose,
    __in    HANDLE Handle
);

//
// Network Hooks
//

extern HOOKDEF(HRESULT, WINAPI, URLDownloadToFileW,
    LPUNKNOWN pCaller,
    LPWSTR szURL,
    LPWSTR szFileName,
    DWORD dwReserved,
    LPVOID lpfnCB
);

extern HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlA,
  __in  HINTERNET hInternet,
  __in  LPCTSTR lpszUrl,
  __in  LPCTSTR lpszHeaders,
  __in  DWORD dwHeadersLength,
  __in  DWORD dwFlags,
  __in  DWORD_PTR dwContext
);

extern HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlW,
  __in  HINTERNET hInternet,
  __in  LPWSTR lpszUrl,
  __in  LPWSTR lpszHeaders,
  __in  DWORD dwHeadersLength,
  __in  DWORD dwFlags,
  __in  DWORD_PTR dwContext
);

extern HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestA,
  __in  HINTERNET hConnect,
  __in  LPCTSTR lpszVerb,
  __in  LPCTSTR lpszObjectName,
  __in  LPCTSTR lpszVersion,
  __in  LPCTSTR lpszReferer,
  __in  LPCTSTR *lplpszAcceptTypes,
  __in  DWORD dwFlags,
  __in  DWORD_PTR dwContext
);

extern HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestW,
  __in  HINTERNET hConnect,
  __in  LPWSTR lpszVerb,
  __in  LPWSTR lpszObjectName,
  __in  LPWSTR lpszVersion,
  __in  LPWSTR lpszReferer,
  __in  LPWSTR *lplpszAcceptTypes,
  __in  DWORD dwFlags,
  __in  DWORD_PTR dwContext
);

extern HOOKDEF(BOOL, WINAPI, HttpSendRequestA,
  __in  HINTERNET hRequest,
  __in  LPCTSTR lpszHeaders,
  __in  DWORD dwHeadersLength,
  __in  LPVOID lpOptional,
  __in  DWORD dwOptionalLength
);

extern HOOKDEF(BOOL, WINAPI, HttpSendRequestW,
  __in  HINTERNET hRequest,
  __in  LPWSTR lpszHeaders,
  __in  DWORD dwHeadersLength,
  __in  LPVOID lpOptional,
  __in  DWORD dwOptionalLength
);

extern HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_A,
  __in         PCSTR lpstrName,
  __in         WORD wType,
  __in         DWORD Options,
  __inout_opt  PVOID pExtra,
  __out_opt    PDNS_RECORD *ppQueryResultsSet,
  __out_opt    PVOID *pReserved
);

extern HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_UTF8,
  __in         LPBYTE lpstrName,
  __in         WORD wType,
  __in         DWORD Options,
  __inout_opt  PVOID pExtra,
  __out_opt    PDNS_RECORD *ppQueryResultsSet,
  __out_opt    PVOID *pReserved
);

extern HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_W,
  __in         PWSTR lpstrName,
  __in         WORD wType,
  __in         DWORD Options,
  __inout_opt  PVOID pExtra,
  __out_opt    PDNS_RECORD *ppQueryResultsSet,
  __out_opt    PVOID *pReserved
);

extern HOOKDEF(int, WSAAPI, getaddrinfo,
  _In_opt_  PCSTR pNodeName,
  _In_opt_  PCSTR pServiceName,
  _In_opt_  const ADDRINFOA *pHints,
  _Out_     PADDRINFOA *ppResult
);

extern HOOKDEF(int, WSAAPI, GetAddrInfoW,
  _In_opt_  PCWSTR pNodeName,
  _In_opt_  PCWSTR pServiceName,
  _In_opt_  const ADDRINFOW *pHints,
  _Out_     PADDRINFOW *ppResult
);

//
// Service Hooks
//

extern HOOKDEF(SC_HANDLE, WINAPI, OpenSCManagerA,
  __in_opt  LPCTSTR lpMachineName,
  __in_opt  LPCTSTR lpDatabaseName,
  __in      DWORD dwDesiredAccess
);

extern HOOKDEF(SC_HANDLE, WINAPI, OpenSCManagerW,
  __in_opt  LPWSTR lpMachineName,
  __in_opt  LPWSTR lpDatabaseName,
  __in      DWORD dwDesiredAccess
);

extern HOOKDEF(SC_HANDLE, WINAPI, CreateServiceA,
  __in       SC_HANDLE hSCManager,
  __in       LPCTSTR lpServiceName,
  __in_opt   LPCTSTR lpDisplayName,
  __in       DWORD dwDesiredAccess,
  __in       DWORD dwServiceType,
  __in       DWORD dwStartType,
  __in       DWORD dwErrorControl,
  __in_opt   LPCTSTR lpBinaryPathName,
  __in_opt   LPCTSTR lpLoadOrderGroup,
  __out_opt  LPDWORD lpdwTagId,
  __in_opt   LPCTSTR lpDependencies,
  __in_opt   LPCTSTR lpServiceStartName,
  __in_opt   LPCTSTR lpPassword
);

extern HOOKDEF(SC_HANDLE, WINAPI, CreateServiceW,
  __in       SC_HANDLE hSCManager,
  __in       LPWSTR lpServiceName,
  __in_opt   LPWSTR lpDisplayName,
  __in       DWORD dwDesiredAccess,
  __in       DWORD dwServiceType,
  __in       DWORD dwStartType,
  __in       DWORD dwErrorControl,
  __in_opt   LPWSTR lpBinaryPathName,
  __in_opt   LPWSTR lpLoadOrderGroup,
  __out_opt  LPDWORD lpdwTagId,
  __in_opt   LPWSTR lpDependencies,
  __in_opt   LPWSTR lpServiceStartName,
  __in_opt   LPWSTR lpPassword
);

extern HOOKDEF(SC_HANDLE, WINAPI, OpenServiceA,
  __in  SC_HANDLE hSCManager,
  __in  LPCTSTR lpServiceName,
  __in  DWORD dwDesiredAccess
);

extern HOOKDEF(SC_HANDLE, WINAPI, OpenServiceW,
  __in  SC_HANDLE hSCManager,
  __in  LPWSTR lpServiceName,
  __in  DWORD dwDesiredAccess
);

extern HOOKDEF(BOOL, WINAPI, StartServiceA,
  __in      SC_HANDLE hService,
  __in      DWORD dwNumServiceArgs,
  __in_opt  LPCTSTR *lpServiceArgVectors
);

extern HOOKDEF(BOOL, WINAPI, StartServiceW,
  __in      SC_HANDLE hService,
  __in      DWORD dwNumServiceArgs,
  __in_opt  LPWSTR *lpServiceArgVectors
);

extern HOOKDEF(BOOL, WINAPI, ControlService,
  __in   SC_HANDLE hService,
  __in   DWORD dwControl,
  __out  LPSERVICE_STATUS lpServiceStatus
);

extern HOOKDEF(BOOL, WINAPI, DeleteService,
  __in  SC_HANDLE hService
);

//
// Special Hooks
//

extern HOOKDEF2(NTSTATUS, WINAPI, NtResumeThread,
    __in        HANDLE ThreadHandle,
    __out_opt   PULONG SuspendCount
);

extern HOOKDEF2(NTSTATUS, WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    ULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
);
