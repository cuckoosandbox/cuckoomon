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

extern HOOKDEF(NTSTATUS, WINAPI, NtDeleteFile,
    __in  POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDeviceIoControlFile,
    __in   HANDLE FileHandle,
    __in   HANDLE Event,
    __in   PIO_APC_ROUTINE ApcRoutine,
    __in   PVOID ApcContext,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   ULONG IoControlCode,
    __in   PVOID InputBuffer,
    __in   ULONG InputBufferLength,
    __out  PVOID OutputBuffer,
    __in   ULONG OutputBufferLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryDirectoryFile,
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __out     PVOID FileInformation,
    __in      ULONG Length,
    __in      FILE_INFORMATION_CLASS FileInformationClass,
    __in      BOOLEAN ReturnSingleEntry,
    __in_opt  PUNICODE_STRING FileName,
    __in      BOOLEAN RestartScan
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationFile,
    __in   HANDLE FileHandle,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __out  PVOID FileInformation,
    __in   ULONG Length,
    __in   FILE_INFORMATION_CLASS FileInformationClass
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSetInformationFile,
    __in   HANDLE FileHandle,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   PVOID FileInformation,
    __in   ULONG Length,
    __in   FILE_INFORMATION_CLASS FileInformationClass
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateDirectoryObject,
    __out  PHANDLE DirectoryHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(BOOL, WINAPI, MoveFileWithProgressW,
  __in      LPWSTR lpExistingFileName,
  __in_opt  LPWSTR lpNewFileName,
  __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
  __in_opt  LPVOID lpData,
  __in      DWORD dwFlags
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

extern HOOKDEF(BOOL, WINAPI, RemoveDirectoryA,
    __in  LPCTSTR  lpPathName
);

extern HOOKDEF(BOOL, WINAPI, RemoveDirectoryW,
    __in  LPWSTR lpPathName
);

extern HOOKDEF(BOOL, WINAPI, MoveFileWithProgressW,
  __in      LPWSTR lpExistingFileName,
  __in_opt  LPWSTR lpNewFileName,
  __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
  __in_opt  LPVOID lpData,
  __in      DWORD dwFlags
);

extern HOOKDEF(HANDLE, WINAPI, FindFirstFileExA,
    __in        LPCTSTR lpFileName,
    __in        FINDEX_INFO_LEVELS fInfoLevelId,
    __out       LPVOID lpFindFileData,
    __in        FINDEX_SEARCH_OPS fSearchOp,
    __reserved  LPVOID lpSearchFilter,
    __in        DWORD dwAdditionalFlags
);

extern HOOKDEF(HANDLE, WINAPI, FindFirstFileExW,
    __in        LPWSTR lpFileName,
    __in        FINDEX_INFO_LEVELS fInfoLevelId,
    __out       LPVOID lpFindFileData,
    __in        FINDEX_SEARCH_OPS fSearchOp,
    __reserved  LPVOID lpSearchFilter,
    __in        DWORD dwAdditionalFlags
);

extern HOOKDEF(BOOL, WINAPI, CopyFileA,
    __in  LPCTSTR lpExistingFileName,
    __in  LPCTSTR lpNewFileName,
    __in  BOOL bFailIfExists
);

extern HOOKDEF(BOOL, WINAPI, CopyFileW,
    __in  LPWSTR lpExistingFileName,
    __in  LPWSTR lpNewFileName,
    __in  BOOL bFailIfExists
);

extern HOOKDEF(BOOL, WINAPI, DeleteFileA,
    __in  LPCSTR lpFileName
);

extern HOOKDEF(BOOL, WINAPI, DeleteFileW,
    __in  LPWSTR lpFileName
);

//
// Registry Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateKey,
    __out       PHANDLE KeyHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in        POBJECT_ATTRIBUTES ObjectAttributes,
    __reserved  ULONG TitleIndex,
    __in_opt    PUNICODE_STRING Class,
    __in        ULONG CreateOptions,
    __out_opt   PULONG Disposition
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenKey,
    __out  PHANDLE KeyHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenKeyEx,
    __out  PHANDLE KeyHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __in   ULONG OpenOptions
);

extern HOOKDEF(NTSTATUS, WINAPI, NtRenameKey,
    __in  HANDLE KeyHandle,
    __in  PUNICODE_STRING NewName
);

extern HOOKDEF(NTSTATUS, WINAPI, NtReplaceKey,
    __in  POBJECT_ATTRIBUTES NewHiveFileName,
    __in  HANDLE KeyHandle,
    __in  POBJECT_ATTRIBUTES BackupHiveFileName
);

extern HOOKDEF(NTSTATUS, WINAPI, NtEnumerateKey,
    __in       HANDLE KeyHandle,
    __in       ULONG Index,
    __in       KEY_INFORMATION_CLASS KeyInformationClass,
    __out_opt  PVOID KeyInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtEnumerateValueKey,
    __in       HANDLE KeyHandle,
    __in       ULONG Index,
    __in       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    __out_opt  PVOID KeyValueInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSetValueKey,
    __in      HANDLE KeyHandle,
    __in      PUNICODE_STRING ValueName,
    __in_opt  ULONG TitleIndex,
    __in      ULONG Type,
    __in_opt  PVOID Data,
    __in      ULONG DataSize
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryValueKey,
    __in       HANDLE KeyHandle,
    __in       PUNICODE_STRING ValueName,
    __in       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    __out_opt  PVOID KeyValueInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryMultipleValueKey,
    __in       HANDLE KeyHandle,
    __inout    PKEY_VALUE_ENTRY ValueEntries,
    __in       ULONG EntryCount,
    __out      PVOID ValueBuffer,
    __inout    PULONG BufferLength,
    __out_opt  PULONG RequiredBufferLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDeleteKey,
    __in  HANDLE KeyHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtDeleteValueKey,
    __in  HANDLE KeyHandle,
    __in  PUNICODE_STRING ValueName
);

extern HOOKDEF(NTSTATUS, WINAPI, NtLoadKey,
    __in  POBJECT_ATTRIBUTES TargetKey,
    __in  POBJECT_ATTRIBUTES SourceFile
);

extern HOOKDEF(NTSTATUS, WINAPI, NtLoadKey2,
    __in  POBJECT_ATTRIBUTES TargetKey,
    __in  POBJECT_ATTRIBUTES SourceFile,
    __in  ULONG Flags
);

extern HOOKDEF(NTSTATUS, WINAPI, NtLoadKeyEx,
    __in      POBJECT_ATTRIBUTES TargetKey,
    __in      POBJECT_ATTRIBUTES SourceFile,
    __in      ULONG Flags,
    __in_opt  HANDLE TrustClassKey
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQueryKey,
    __in       HANDLE KeyHandle,
    __in       KEY_INFORMATION_CLASS KeyInformationClass,
    __out_opt  PVOID KeyInformation,
    __in       ULONG Length,
    __out      PULONG ResultLength
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSaveKey,
    __in  HANDLE KeyHandle,
    __in  HANDLE FileHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtSaveKeyEx,
    __in  HANDLE KeyHandle,
    __in  HANDLE FileHandle,
    __in  ULONG Format
);

extern HOOKDEF(LONG, WINAPI, RegQueryInfoKeyA,
    _In_         HKEY hKey,
    _Out_opt_    LPTSTR lpClass,
    _Inout_opt_  LPDWORD lpcClass,
    _Reserved_   LPDWORD lpReserved,
    _Out_opt_    LPDWORD lpcSubKeys,
    _Out_opt_    LPDWORD lpcMaxSubKeyLen,
    _Out_opt_    LPDWORD lpcMaxClassLen,
    _Out_opt_    LPDWORD lpcValues,
    _Out_opt_    LPDWORD lpcMaxValueNameLen,
    _Out_opt_    LPDWORD lpcMaxValueLen,
    _Out_opt_    LPDWORD lpcbSecurityDescriptor,
    _Out_opt_    PFILETIME lpftLastWriteTime
);

extern HOOKDEF(LONG, WINAPI, RegQueryInfoKeyW,
    _In_         HKEY hKey,
    _Out_opt_    LPWSTR lpClass,
    _Inout_opt_  LPDWORD lpcClass,
    _Reserved_   LPDWORD lpReserved,
    _Out_opt_    LPDWORD lpcSubKeys,
    _Out_opt_    LPDWORD lpcMaxSubKeyLen,
    _Out_opt_    LPDWORD lpcMaxClassLen,
    _Out_opt_    LPDWORD lpcValues,
    _Out_opt_    LPDWORD lpcMaxValueNameLen,
    _Out_opt_    LPDWORD lpcMaxValueLen,
    _Out_opt_    LPDWORD lpcbSecurityDescriptor,
    _Out_opt_    PFILETIME lpftLastWriteTime
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

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenProcess,
    __out     PHANDLE ProcessHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PCLIENT_ID ClientId
);

extern HOOKDEF(NTSTATUS, WINAPI, NtTerminateProcess,
    __in_opt  HANDLE ProcessHandle,
    __in      NTSTATUS ExitStatus
);

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateSection,
    __out     PHANDLE SectionHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  PLARGE_INTEGER MaximumSize,
    __in      ULONG SectionPageProtection,
    __in      ULONG AllocationAttributes,
    __in_opt  HANDLE FileHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenSection,
    __out  PHANDLE SectionHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
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

extern HOOKDEF(VOID, WINAPI, ExitProcess,
  __in  UINT uExitCode
);

extern HOOKDEF(BOOL, WINAPI, ShellExecuteExW,
  __inout  SHELLEXECUTEINFOW *pExecInfo
);

extern HOOKDEF(NTSTATUS, WINAPI, NtAllocateVirtualMemory,
    __in     HANDLE ProcessHandle,
    __inout  PVOID *BaseAddress,
    __in     ULONG_PTR ZeroBits,
    __inout  PSIZE_T RegionSize,
    __in     ULONG AllocationType,
    __in     ULONG Protect
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

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateThread,
    __out     PHANDLE ThreadHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in_opt  POBJECT_ATTRIBUTES ObjectAttributes,
    __in       HANDLE ProcessHandle,
    __out      PCLIENT_ID ClientId,
    __in       PCONTEXT ThreadContext,
    __in        PINITIAL_TEB InitialTeb,
    __in      BOOLEAN CreateSuspended
);

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenThread,
    __out  PHANDLE ThreadHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __in   PCLIENT_ID ClientId
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
    __in       HANDLE ThreadHandle,
    __out_opt  ULONG *PreviousSuspendCount
);

extern HOOKDEF(NTSTATUS, WINAPI, NtResumeThread,
    __in        HANDLE ThreadHandle,
    __out_opt   ULONG *SuspendCount
);

extern HOOKDEF(NTSTATUS, WINAPI, NtTerminateThread,
    __in  HANDLE ThreadHandle,
    __in  NTSTATUS ExitStatus
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
