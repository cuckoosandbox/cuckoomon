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

#include <windns.h>
#include <wininet.h>
#include <mswsock.h>
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

extern HOOKDEF(NTSTATUS, WINAPI, NtOpenDirectoryObject,
    __out  PHANDLE DirectoryHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
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

extern HOOKDEF(BOOL, WINAPI, CopyFileExW,
    _In_      LPWSTR lpExistingFileName,
    _In_      LPWSTR lpNewFileName,
    _In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_  LPVOID lpData,
    _In_opt_  LPBOOL pbCancel,
    _In_      DWORD dwCopyFlags
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

extern HOOKDEF(LONG, WINAPI, RegCloseKey,
    __in    HKEY hKey
);

//
// Native Registry Hooks
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

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateNamedPipeFile,
    OUT         PHANDLE NamedPipeFileHandle,
    IN          ACCESS_MASK DesiredAccess,
    IN          POBJECT_ATTRIBUTES ObjectAttributes,
    OUT         PIO_STATUS_BLOCK IoStatusBlock,
    IN          ULONG ShareAccess,
    IN          ULONG CreateDisposition,
    IN          ULONG CreateOptions,
    IN          BOOLEAN WriteModeMessage,
    IN          BOOLEAN ReadModeMessage,
    IN          BOOLEAN NonBlocking,
    IN          ULONG MaxInstances,
    IN          ULONG InBufferSize,
    IN          ULONG OutBufferSize,
    IN          PLARGE_INTEGER DefaultTimeOut
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

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateUserProcess,
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
);

extern HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserProcess,
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

extern HOOKDEF(NTSTATUS, WINAPI, NtMakeTemporaryObject,
    __in     HANDLE ObjectHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, NtMakePermanentObject,
    __in     HANDLE ObjectHandle
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

extern HOOKDEF2(BOOL, WINAPI, CreateProcessInternalW,
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

extern HOOKDEF(NTSTATUS, WINAPI, NtUnmapViewOfSection,
    _In_      HANDLE ProcessHandle,
    _In_opt_  PVOID BaseAddress
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

extern HOOKDEF(BOOL, WINAPI, ReadProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPCVOID lpBaseAddress,
    _Out_   LPVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   SIZE_T *lpNumberOfBytesRead
);

extern HOOKDEF(NTSTATUS, WINAPI, NtWriteVirtualMemory,
    __in        HANDLE ProcessHandle,
    __in        LPVOID BaseAddress,
    __in        LPCVOID Buffer,
    __in        ULONG NumberOfBytesToWrite,
    __out_opt   ULONG *NumberOfBytesWritten
);

extern HOOKDEF(BOOL, WINAPI, WriteProcessMemory,
    _In_    HANDLE hProcess,
    _In_    LPVOID lpBaseAddress,
    _In_    LPCVOID lpBuffer,
    _In_    SIZE_T nSize,
    _Out_   SIZE_T *lpNumberOfBytesWritten
);

extern HOOKDEF(NTSTATUS, WINAPI, NtProtectVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN OUT  PVOID *BaseAddress,
    IN OUT  PULONG NumberOfBytesToProtect,
    IN      ULONG NewAccessProtection,
    OUT     PULONG OldAccessProtection
);

extern HOOKDEF(BOOL, WINAPI, VirtualProtectEx,
    __in   HANDLE hProcess,
    __in   LPVOID lpAddress,
    __in   SIZE_T dwSize,
    __in   DWORD flNewProtect,
    __out  PDWORD lpflOldProtect
);

extern HOOKDEF(NTSTATUS, WINAPI, NtFreeVirtualMemory,
    IN      HANDLE ProcessHandle,
    IN      PVOID *BaseAddress,
    IN OUT  PULONG RegionSize,
    IN      ULONG FreeType
);

extern HOOKDEF(BOOL, WINAPI, VirtualFreeEx,
    __in  HANDLE hProcess,
    __in  LPVOID lpAddress,
    __in  SIZE_T dwSize,
    __in  DWORD dwFreeType
);

extern HOOKDEF(int, CDECL, system,
    const char *command
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

extern HOOKDEF(NTSTATUS, WINAPI, NtCreateThreadEx,
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

extern HOOKDEF(NTSTATUS, WINAPI, RtlCreateUserThread,
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

extern HOOKDEF(BOOL, WINAPI, WriteConsoleA,
    _In_        HANDLE hConsoleOutput,
    _In_        const VOID *lpBuffer,
    _In_        DWORD nNumberOfCharsToWrite,
    _Out_       LPDWORD lpNumberOfCharsWritten,
    _Reserved_  LPVOID lpReseverd
);

extern HOOKDEF(BOOL, WINAPI, WriteConsoleW,
    _In_        HANDLE hConsoleOutput,
    _In_        const VOID *lpBuffer,
    _In_        DWORD nNumberOfCharsToWrite,
    _Out_       LPDWORD lpNumberOfCharsWritten,
    _Reserved_  LPVOID lpReseverd
);

extern HOOKDEF(int, WINAPI, GetSystemMetrics,
    _In_  int nIndex
);

extern HOOKDEF(BOOL, WINAPI, GetCursorPos,
    _Out_ LPPOINT lpPoint
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

extern HOOKDEF(HINTERNET, WINAPI, InternetOpenA,
    _In_  LPCTSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPCTSTR lpszProxyName,
    _In_  LPCTSTR lpszProxyBypass,
    _In_  DWORD dwFlags
);

extern HOOKDEF(HINTERNET, WINAPI, InternetOpenW,
    _In_  LPWSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPWSTR lpszProxyName,
    _In_  LPWSTR lpszProxyBypass,
    _In_  DWORD dwFlags
);

extern HOOKDEF(HINTERNET, WINAPI, InternetConnectA,
    _In_  HINTERNET hInternet,
    _In_  LPCTSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPCTSTR lpszUsername,
    _In_  LPCTSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
);

extern HOOKDEF(HINTERNET, WINAPI, InternetConnectW,
    _In_  HINTERNET hInternet,
    _In_  LPWSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPWSTR lpszUsername,
    _In_  LPWSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
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

extern HOOKDEF(BOOL, WINAPI, InternetReadFile,
    _In_   HINTERNET hFile,
    _Out_  LPVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToRead,
    _Out_  LPDWORD lpdwNumberOfBytesRead
);

extern HOOKDEF(BOOL, WINAPI, InternetWriteFile,
    _In_   HINTERNET hFile,
    _In_   LPCVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToWrite,
    _Out_  LPDWORD lpdwNumberOfBytesWritten
);

extern HOOKDEF(BOOL, WINAPI, InternetCloseHandle,
    _In_  HINTERNET hInternet
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
// Sleep Hooks
//

extern HOOKDEF(NTSTATUS, WINAPI, NtDelayExecution,
    __in    BOOLEAN Alertable,
    __in    PLARGE_INTEGER DelayInterval
);

extern HOOKDEF(void, WINAPI, GetLocalTime,
    __out  LPSYSTEMTIME lpSystemTime
);

extern HOOKDEF(void, WINAPI, GetSystemTime,
    __out  LPSYSTEMTIME lpSystemTime
);

extern HOOKDEF(DWORD, WINAPI, GetTickCount,
    void
);

extern HOOKDEF(NTSTATUS, WINAPI, NtQuerySystemTime,
    _Out_  PLARGE_INTEGER SystemTime
);

//
// Socket Hooks
//

extern HOOKDEF(int, WINAPI, WSAStartup,
    _In_   WORD wVersionRequested,
    _Out_  LPWSADATA lpWSAData
);

extern HOOKDEF(struct hostent *, WSAAPI, gethostbyname,
    __in  const char *name
);

extern HOOKDEF(SOCKET, WSAAPI, socket,
    __in  int af,
    __in  int type,
    __in  int protocol
);

extern HOOKDEF(int, WSAAPI, connect,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
);

extern HOOKDEF(int, WSAAPI, send,
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags
);

extern HOOKDEF(int, WSAAPI, sendto,
    __in  SOCKET s,
    __in  const char *buf,
    __in  int len,
    __in  int flags,
    __in  const struct sockaddr *to,
    __in  int tolen
);

extern HOOKDEF(int, WSAAPI, recv,
    __in   SOCKET s,
    __out  char *buf,
    __in   int len,
    __in   int flags
);

extern HOOKDEF(int, WSAAPI, recvfrom,
    __in         SOCKET s,
    __out        char *buf,
    __in         int len,
    __in         int flags,
    __out        struct sockaddr *from,
    __inout_opt  int *fromlen
);

extern HOOKDEF(SOCKET, WSAAPI, accept,
    __in     SOCKET s,
    __out    struct sockaddr *addr,
    __inout  int *addrlen
);

extern HOOKDEF(int, WSAAPI, bind,
    __in  SOCKET s,
    __in  const struct sockaddr *name,
    __in  int namelen
);

extern HOOKDEF(int, WSAAPI, listen,
    __in  SOCKET s,
    __in  int backlog
);

extern HOOKDEF(int, WSAAPI, select,
    __in     SOCKET s,
    __inout  fd_set *readfds,
    __inout  fd_set *writefds,
    __inout  fd_set *exceptfds,
    __in     const struct timeval *timeout
);

extern HOOKDEF(int, WSAAPI, setsockopt,
    __in  SOCKET s,
    __in  int level,
    __in  int optname,
    __in  const char *optval,
    __in  int optlen
);

extern HOOKDEF(int, WSAAPI, ioctlsocket,
    __in     SOCKET s,
    __in     long cmd,
    __inout  u_long *argp
);

extern HOOKDEF(int, WSAAPI, closesocket,
    __in  SOCKET s
);

extern HOOKDEF(int, WSAAPI, shutdown,
    __in  SOCKET s,
    __in  int how
);

extern HOOKDEF(int, WSAAPI, WSARecv,
    __in     SOCKET s,
    __inout  LPWSABUF lpBuffers,
    __in     DWORD dwBufferCount,
    __out    LPDWORD lpNumberOfBytesRecvd,
    __inout  LPDWORD lpFlags,
    __in     LPWSAOVERLAPPED lpOverlapped,
    __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

extern HOOKDEF(int, WSAAPI, WSARecvFrom,
    __in     SOCKET s,
    __inout  LPWSABUF lpBuffers,
    __in     DWORD dwBufferCount,
    __out    LPDWORD lpNumberOfBytesRecvd,
    __inout  LPDWORD lpFlags,
    __out    struct sockaddr *lpFrom,
    __inout  LPINT lpFromlen,
    __in     LPWSAOVERLAPPED lpOverlapped,
    __in     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

extern HOOKDEF(int, WSAAPI, WSASend,
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

extern HOOKDEF(int, WSAAPI, WSASendTo,
    __in   SOCKET s,
    __in   LPWSABUF lpBuffers,
    __in   DWORD dwBufferCount,
    __out  LPDWORD lpNumberOfBytesSent,
    __in   DWORD dwFlags,
    __in   const struct sockaddr *lpTo,
    __in   int iToLen,
    __in   LPWSAOVERLAPPED lpOverlapped,
    __in   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

extern HOOKDEF(SOCKET, WSAAPI, WSASocketA,
    __in  int af,
    __in  int type,
    __in  int protocol,
    __in  LPWSAPROTOCOL_INFO lpProtocolInfo,
    __in  GROUP g,
    __in  DWORD dwFlags
);

extern HOOKDEF(SOCKET, WSAAPI, WSASocketW,
    __in  int af,
    __in  int type,
    __in  int protocol,
    __in  LPWSAPROTOCOL_INFO lpProtocolInfo,
    __in  GROUP g,
    __in  DWORD dwFlags
);


extern HOOKDEF(BOOL, PASCAL, ConnectEx,
    _In_      SOCKET s,
    _In_      const struct sockaddr *name,
    _In_      int namelen,
    _In_opt_  PVOID lpSendBuffer,
    _In_      DWORD dwSendDataLength,
    _Out_     LPDWORD lpdwBytesSent,
    _In_      LPOVERLAPPED lpOverlapped
);

extern HOOKDEF(BOOL, PASCAL, TransmitFile,
    SOCKET hSocket,
    HANDLE hFile,
    DWORD nNumberOfBytesToWrite,
    DWORD nNumberOfBytesPerSend,
    LPOVERLAPPED lpOverlapped,
    LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    DWORD dwFlags
);

//
// Special Hooks
//

extern HOOKDEF2(NTSTATUS, WINAPI, LdrLoadDll,
    __in_opt    PWCHAR PathToFile,
    __in_opt    ULONG Flags,
    __in        PUNICODE_STRING ModuleFileName,
    __out       PHANDLE ModuleHandle
);

extern HOOKDEF(NTSTATUS, WINAPI, ZwMapViewOfSection,
    _In_     HANDLE SectionHandle,
    _In_     HANDLE ProcessHandle,
    __inout  PVOID *BaseAddress,
    _In_     ULONG_PTR ZeroBits,
    _In_     SIZE_T CommitSize,
    __inout  PLARGE_INTEGER SectionOffset,
    __inout  PSIZE_T ViewSize,
    __in     UINT InheritDisposition,
    __in     ULONG AllocationType,
    __in     ULONG Win32Protect
);
