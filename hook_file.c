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
#include <ctype.h>
#include <windows.h>
#include <shlwapi.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"
#include "pipe.h"
#include "misc.h"
#include "ignore.h"
#include "lookup.h"

static IS_SUCCESS_NTSTATUS();

#define DUMP_FILE_MASK (GENERIC_WRITE | FILE_GENERIC_WRITE | \
    FILE_WRITE_DATA | FILE_APPEND_DATA | STANDARD_RIGHTS_WRITE | \
    STANDARD_RIGHTS_ALL)

#define HDDVOL1 L"\\Device\\HarddiskVolume1"

// length of a hardcoded unicode string
#define UNILEN(x) (sizeof(x) / sizeof(wchar_t) - 1)

typedef struct _file_record_t {
    unsigned int attributes;
    size_t length;
    wchar_t filename[0];
} file_record_t;

static lookup_t g_files;

void file_init()
{
    lookup_init(&g_files);
}

static void new_file(const UNICODE_STRING *obj)
{
    const wchar_t *str = obj->Buffer;
    unsigned int len = obj->Length / sizeof(wchar_t);

    // if it's a path including \??\ then we can send it straight away,
    // but we strip the \??\ part
    if(len > 4 && !wcsncmp(str, L"\\??\\", 4)) {
        pipe("FILE_NEW:%S", len - 4, str + 4);
    }
    // maybe it's an absolute path (or a relative path with a harddisk,
    // such as C:abc.txt)
    else if(isalpha(str[0]) != 0 && str[1] == ':') {
        pipe("FILE_NEW:%S", len, str);
    }
    // the filename starts with \Device\HarddiskVolume1, which is
    // basically just C:
    else if(!wcsnicmp(str, HDDVOL1, UNILEN(HDDVOL1))) {
        str += UNILEN(HDDVOL1), len -= UNILEN(HDDVOL1);
        pipe("FILE_NEW:C:%S", len, str);
    }
}

static void cache_file(HANDLE file_handle, const wchar_t *path,
    unsigned int length, unsigned int attributes)
{
    file_record_t *r = lookup_add(&g_files, (unsigned int) file_handle,
        sizeof(file_record_t) + length * sizeof(wchar_t) + sizeof(wchar_t));

    *r = (file_record_t) {
        .attributes = attributes,
        .length     = length,
    };

    wcsncpy(r->filename, path, r->length + 1);
}

static void file_write(HANDLE file_handle)
{
    file_record_t *r = lookup_get(&g_files, (unsigned int) file_handle, NULL);
    if(r != NULL) {
        UNICODE_STRING str = {
            // microsoft actually meant "size"
            .Length         = r->length * sizeof(wchar_t),
            .MaximumLength  = (r->length + 1) * sizeof(wchar_t) ,
            .Buffer         = r->filename,
        };

        // we do in fact want to dump this file because it was written to
        new_file(&str);

        // delete the file record from the list
        lookup_del(&g_files, (unsigned int) file_handle);
    }
}

static void handle_new_file(HANDLE file_handle, const OBJECT_ATTRIBUTES *obj)
{
    if(is_directory_objattr(obj) == 0 && is_ignored_file_objattr(obj) == 0) {

        wchar_t fname[MAX_PATH_PLUS_TOLERANCE]; uint32_t length;

        length = path_from_object_attributes(obj,
            fname, MAX_PATH_PLUS_TOLERANCE);

        length = ensure_absolute_path(fname, fname, length);

        // cache this file
        cache_file(file_handle, fname, length, obj->Attributes);
    }
}

void file_close(HANDLE file_handle)
{
    lookup_del(&g_files, (unsigned int) file_handle);
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateFile,
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
) {
    NTSTATUS ret = Old_NtCreateFile(FileHandle, DesiredAccess,
        ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
        ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
    LOQ("PpOll", "FileHandle", FileHandle, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes, "CreateDisposition", CreateDisposition,
        "ShareAccess", ShareAccess);
    if(NT_SUCCESS(ret) && DesiredAccess & DUMP_FILE_MASK) {
        handle_new_file(*FileHandle, ObjectAttributes);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenFile,
    __out  PHANDLE FileHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   ULONG ShareAccess,
    __in   ULONG OpenOptions
) {
    NTSTATUS ret = Old_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, ShareAccess, OpenOptions);
    LOQ("PpOl", "FileHandle", FileHandle, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes, "ShareAccess", ShareAccess);
    if(NT_SUCCESS(ret) && DesiredAccess & DUMP_FILE_MASK) {
        handle_new_file(*FileHandle, ObjectAttributes);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtReadFile,
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __out     PVOID Buffer,
    __in      ULONG Length,
    __in_opt  PLARGE_INTEGER ByteOffset,
    __in_opt  PULONG Key
) {
    NTSTATUS ret = Old_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, Buffer, Length, ByteOffset, Key);
    LOQ("pb", "FileHandle", FileHandle,
        "Buffer", IoStatusBlock->Information, Buffer);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtWriteFile,
    __in      HANDLE FileHandle,
    __in_opt  HANDLE Event,
    __in_opt  PIO_APC_ROUTINE ApcRoutine,
    __in_opt  PVOID ApcContext,
    __out     PIO_STATUS_BLOCK IoStatusBlock,
    __in      PVOID Buffer,
    __in      ULONG Length,
    __in_opt  PLARGE_INTEGER ByteOffset,
    __in_opt  PULONG Key
) {
    NTSTATUS ret = Old_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, Buffer, Length, ByteOffset, Key);
    LOQ("pb", "FileHandle", FileHandle,
        "Buffer", IoStatusBlock->Information, Buffer);
    if(NT_SUCCESS(ret)) {
        file_write(FileHandle);
    }
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeleteFile,
    __in  POBJECT_ATTRIBUTES ObjectAttributes
) {
    pipe("FILE_DEL:%O", ObjectAttributes);

    NTSTATUS ret = Old_NtDeleteFile(ObjectAttributes);
    LOQ("O", "FileName", ObjectAttributes);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeviceIoControlFile,
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
) {
    NTSTATUS ret = Old_NtDeviceIoControlFile(FileHandle, Event,
        ApcRoutine, ApcContext, IoStatusBlock, IoControlCode,
        InputBuffer, InputBufferLength, OutputBuffer,
        OutputBufferLength);
    LOQ("pbb", "FileHandle", FileHandle,
        "InputBuffer", InputBufferLength, InputBuffer,
        "OutputBuffer", IoStatusBlock->Information, OutputBuffer);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryDirectoryFile,
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
) {
    NTSTATUS ret = Old_NtQueryDirectoryFile(FileHandle, Event,
        ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
        Length, FileInformationClass, ReturnSingleEntry,
        FileName, RestartScan);
    LOQ("pbo", "FileHandle", FileHandle,
        "FileInformation", IoStatusBlock->Information, FileInformation,
        "FileName", FileName);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInformationFile,
    __in   HANDLE FileHandle,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __out  PVOID FileInformation,
    __in   ULONG Length,
    __in   FILE_INFORMATION_CLASS FileInformationClass
) {
    NTSTATUS ret = Old_NtQueryInformationFile(FileHandle, IoStatusBlock,
        FileInformation, Length, FileInformationClass);
    LOQ("pb", "FileHandle", FileHandle,
        "FileInformation", IoStatusBlock->Information, FileInformation);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtSetInformationFile,
    __in   HANDLE FileHandle,
    __out  PIO_STATUS_BLOCK IoStatusBlock,
    __in   PVOID FileInformation,
    __in   ULONG Length,
    __in   FILE_INFORMATION_CLASS FileInformationClass
) {
    if(FileInformation != NULL && Length == sizeof(BOOLEAN) &&
            FileInformationClass == FileDispositionInformation &&
            *(BOOLEAN *) FileInformation != FALSE) {

        wchar_t path[MAX_PATH_PLUS_TOLERANCE];
        path_from_handle(FileHandle, path, (unsigned int) MAX_PATH_PLUS_TOLERANCE);
        pipe("FILE_DEL:%Z", path);
    }

    NTSTATUS ret = Old_NtSetInformationFile(FileHandle, IoStatusBlock,
        FileInformation, Length, FileInformationClass);
    LOQ("pb", "FileHandle", FileHandle,
        "FileInformation", IoStatusBlock->Information, FileInformation);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenDirectoryObject,
    __out  PHANDLE DirectoryHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS ret = Old_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess,
        ObjectAttributes);
    LOQ("PlO", "DirectoryHandle", DirectoryHandle,
        "DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtCreateDirectoryObject,
    __out  PHANDLE DirectoryHandle,
    __in   ACCESS_MASK DesiredAccess,
    __in   POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS ret = Old_NtCreateDirectoryObject(DirectoryHandle, DesiredAccess,
        ObjectAttributes);
    LOQ("PlO", "DirectoryHandle", DirectoryHandle,
        "DesiredAccess", DesiredAccess, "ObjectAttributes", ObjectAttributes);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CreateDirectoryW,
    __in      LPWSTR lpPathName,
    __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_CreateDirectoryW(lpPathName, lpSecurityAttributes);
    LOQ("u", "DirectoryName", lpPathName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CreateDirectoryExW,
    __in      LPWSTR lpTemplateDirectory,
    __in      LPWSTR lpNewDirectory,
    __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_CreateDirectoryExW(lpTemplateDirectory, lpNewDirectory,
        lpSecurityAttributes);
    LOQ("u", "DirectoryName", lpNewDirectory);
    return ret;
}

HOOKDEF(BOOL, WINAPI, RemoveDirectoryA,
    __in  LPCTSTR lpPathName
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_RemoveDirectoryA(lpPathName);
    LOQ("s", "DirectoryName", lpPathName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, RemoveDirectoryW,
    __in  LPWSTR lpPathName
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_RemoveDirectoryW(lpPathName);
    LOQ("u", "DirectoryName", lpPathName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, MoveFileWithProgressW,
    __in      LPWSTR lpExistingFileName,
    __in_opt  LPWSTR lpNewFileName,
    __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
    __in_opt  LPVOID lpData,
    __in      DWORD dwFlags
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_MoveFileWithProgressW(lpExistingFileName, lpNewFileName,
        lpProgressRoutine, lpData, dwFlags);
    LOQ("uu", "ExistingFileName", lpExistingFileName,
        "NewFileName", lpNewFileName);
    if(ret != FALSE) {
        pipe("FILE_MOVE:%Z::%Z", lpExistingFileName, lpNewFileName);
    }
    return ret;
}

HOOKDEF(HANDLE, WINAPI, FindFirstFileExA,
    __in        LPCTSTR lpFileName,
    __in        FINDEX_INFO_LEVELS fInfoLevelId,
    __out       LPVOID lpFindFileData,
    __in        FINDEX_SEARCH_OPS fSearchOp,
    __reserved  LPVOID lpSearchFilter,
    __in        DWORD dwAdditionalFlags
) {
    IS_SUCCESS_HANDLE();

    HANDLE ret = Old_FindFirstFileExA(lpFileName, fInfoLevelId,
        lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    LOQ("s", "FileName", lpFileName);
    return ret;
}

HOOKDEF(HANDLE, WINAPI, FindFirstFileExW,
    __in        LPWSTR lpFileName,
    __in        FINDEX_INFO_LEVELS fInfoLevelId,
    __out       LPVOID lpFindFileData,
    __in        FINDEX_SEARCH_OPS fSearchOp,
    __reserved  LPVOID lpSearchFilter,
    __in        DWORD dwAdditionalFlags
) {
    IS_SUCCESS_HANDLE();

    HANDLE ret = Old_FindFirstFileExW(lpFileName, fInfoLevelId,
        lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    LOQ("u", "FileName", lpFileName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CopyFileA,
    __in  LPCTSTR lpExistingFileName,
    __in  LPCTSTR lpNewFileName,
    __in  BOOL bFailIfExists
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_CopyFileA(lpExistingFileName, lpNewFileName,
        bFailIfExists);
    LOQ("ss", "ExistingFileName", lpExistingFileName,
        "NewFileName", lpNewFileName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CopyFileW,
    __in  LPWSTR lpExistingFileName,
    __in  LPWSTR lpNewFileName,
    __in  BOOL bFailIfExists
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_CopyFileW(lpExistingFileName, lpNewFileName,
        bFailIfExists);
    LOQ("uu", "ExistingFileName", lpExistingFileName,
        "NewFileName", lpNewFileName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CopyFileExW,
    _In_      LPWSTR lpExistingFileName,
    _In_      LPWSTR lpNewFileName,
    _In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_  LPVOID lpData,
    _In_opt_  LPBOOL pbCancel,
    _In_      DWORD dwCopyFlags
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_CopyFileExW(lpExistingFileName, lpNewFileName,
        lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
    LOQ("uul", "ExistingFileName", lpExistingFileName,
        "NewFileName", lpNewFileName, "CopyFlags", dwCopyFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteFileA,
    __in  LPCSTR lpFileName
) {
    IS_SUCCESS_BOOL();

    wchar_t path[MAX_PATH];

    // copy ascii to unicode string
    for (int i = 0; lpFileName[i] != 0 && i < MAX_PATH; i++) {
        path[i] = lpFileName[i];
    }

    ensure_absolute_path(path, path, strlen(lpFileName));

    pipe("FILE_DEL:%Z", path);

    BOOL ret = Old_DeleteFileA(lpFileName);
    LOQ("s", "FileName", lpFileName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteFileW,
    __in  LPWSTR lpFileName
) {
    IS_SUCCESS_BOOL();

    wchar_t path[MAX_PATH];

    ensure_absolute_path(path, lpFileName, lstrlenW(lpFileName));

    pipe("FILE_DEL:%Z", path);

    BOOL ret = Old_DeleteFileW(lpFileName);
    LOQ("u", "FileName", lpFileName);
    return ret;
}
