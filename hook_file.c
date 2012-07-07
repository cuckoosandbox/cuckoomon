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
    LOQ("POl", "FileHandle", FileHandle, "FileName", ObjectAttributes,
        "CreateDisposition", CreateDisposition);
    if(NT_SUCCESS(ret) && DesiredAccess & GENERIC_WRITE) {
        pipe_write("FILE:%.*S", ObjectAttributes->ObjectName->Length >> 1,
            ObjectAttributes->ObjectName->Buffer);
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
    LOQ("PO", "FileHandle", FileHandle, "FileName", ObjectAttributes);
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
    return ret;
}

HOOKDEF(BOOL, WINAPI, DeleteFileW,
  __in  LPWSTR lpFileName
) {
    IS_SUCCESS_BOOL();

    if(lpFileName != NULL) {
        // first obtain the filename
        const wchar_t *pwszFileName = lpFileName;
        for (const wchar_t *p = pwszFileName = lpFileName; *p != 0; p++) {
            if(*p == '/' || *p == '\\') {
                pwszFileName = p + 1;
            }
        }

        // generate an unique path
        wchar_t fname[MAX_PATH];
        do {
            snwprintf(fname, sizeof(fname),
                L"C:\\cuckoo\\files\\%d-%d-%s_", GetCurrentProcessId(),
                rand(), pwszFileName);
        } while (GetFileAttributesW(fname) != INVALID_FILE_ATTRIBUTES);

        // copy the file
        CopyFileW(lpFileName, fname, TRUE);
    }

    BOOL ret = Old_DeleteFileW(lpFileName);
    LOQ("u", "FileName", lpFileName);
    return ret;
}
