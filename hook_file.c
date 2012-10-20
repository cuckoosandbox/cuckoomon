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
#include "pipe.h"
#include "misc.h"

static IS_SUCCESS_NTSTATUS();
static const char *module_name = "filesystem";

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
    LOQ("PlOl", "FileHandle", FileHandle, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes, "CreateDisposition", CreateDisposition);
    if(NT_SUCCESS(ret) && DesiredAccess & GENERIC_WRITE) {
        pipe("FILE_NEW:%O", ObjectAttributes);
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
    LOQ("PlO", "FileHandle", FileHandle, "DesiredAccess", DesiredAccess,
        "FileName", ObjectAttributes);
    if(NT_SUCCESS(ret) && DesiredAccess & GENERIC_WRITE) {
        pipe("FILE_NEW:%O", ObjectAttributes);
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
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtDeleteFile,
    __in  POBJECT_ATTRIBUTES ObjectAttributes
) {
    char buf[4]; int len = sizeof(buf);
    pipe2(buf, &len, "FILE_DEL:%O", ObjectAttributes);

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
    NTSTATUS ret = Old_NtSetInformationFile(FileHandle, IoStatusBlock,
        FileInformation, Length, FileInformationClass);
    LOQ("pb", "FileHandle", FileHandle,
        "FileInformation", IoStatusBlock->Information, FileInformation);
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

    int log_new = 1;

    // if the new filename is null, then this function call is to delete the
    // existing file
    if(lpNewFileName == NULL) {
        char buf[4]; int len = sizeof(buf);
        pipe2(buf, &len, "FILE_DEL:%Z", lpExistingFileName);
        log_new = 0;
    }

    BOOL ret = Old_MoveFileWithProgressW(lpExistingFileName, lpNewFileName,
        lpProgressRoutine, lpData, dwFlags);
    LOQ("uu", "ExistingFileName", lpExistingFileName,
        "NewFileName", lpNewFileName);
    if(ret != FALSE && log_new != 0) {
        pipe("FILE_NEW:%Z", lpNewFileName);
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

HOOKDEF(BOOL, WINAPI, DeleteFileA,
    __in  LPCSTR lpFileName
) {
    IS_SUCCESS_BOOL();

    char buf[4]; int len = sizeof(buf);
    pipe2(buf, &len, "FILE_DEL:%z", lpFileName);

    BOOL ret = Old_DeleteFileA(lpFileName);
    LOQ("s", "FileName", lpFileName);
    return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteFileW,
  __in  LPWSTR lpFileName
) {
    IS_SUCCESS_BOOL();

    char buf[4]; int len = sizeof(buf);
    pipe2(buf, &len, "FILE_DEL:%Z", lpFileName);

    BOOL ret = Old_DeleteFileW(lpFileName);
    LOQ("u", "FileName", lpFileName);
    return ret;
}
