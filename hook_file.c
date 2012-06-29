#include <stdio.h>
#include <windows.h>
#include "ntapi.h"
#include "log.h"

NTSTATUS (WINAPI *Old_NtCreateFile)(
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

NTSTATUS WINAPI New_NtCreateFile(
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
    LOQ("lUl", "FileHandle", *FileHandle,
        "FileName", ObjectAttributes->ObjectName->Length >> 1,
            ObjectAttributes->ObjectName->Buffer,
        "CreateDisposition", CreateDisposition);
    return ret;
}

NTSTATUS (WINAPI *Old_NtOpenFile)(
  __out  PHANDLE FileHandle,
  __in   ACCESS_MASK DesiredAccess,
  __in   POBJECT_ATTRIBUTES ObjectAttributes,
  __out  PIO_STATUS_BLOCK IoStatusBlock,
  __in   ULONG ShareAccess,
  __in   ULONG OpenOptions
);

NTSTATUS WINAPI New_NtOpenFile(
  __out  PHANDLE FileHandle,
  __in   ACCESS_MASK DesiredAccess,
  __in   POBJECT_ATTRIBUTES ObjectAttributes,
  __out  PIO_STATUS_BLOCK IoStatusBlock,
  __in   ULONG ShareAccess,
  __in   ULONG OpenOptions
) {
    NTSTATUS ret = Old_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, ShareAccess, OpenOptions);
    LOQ("lU", "FileHandle", *FileHandle,
        "FileName", ObjectAttributes->ObjectName->Length >> 1,
            ObjectAttributes->ObjectName->Buffer);
    return ret;
}

NTSTATUS (WINAPI *Old_NtReadFile)(
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

NTSTATUS WINAPI New_NtReadFile(
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
    LOQ("lb", "FileHandle", FileHandle,
        "Buffer", IoStatusBlock->Information, Buffer);
    return ret;
}

NTSTATUS (WINAPI *Old_NtWriteFile)(
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

NTSTATUS WINAPI New_NtWriteFile(
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
    LOQ("lb", "FileHandle", FileHandle,
        "Buffer", IoStatusBlock->Information, Buffer);
    return ret;
}

BOOL (WINAPI *Old_MoveFileWithProgressW)(
  __in      LPWSTR lpExistingFileName,
  __in_opt  LPWSTR lpNewFileName,
  __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
  __in_opt  LPVOID lpData,
  __in      DWORD dwFlags
);

BOOL WINAPI New_MoveFileWithProgressW(
  __in      LPWSTR lpExistingFileName,
  __in_opt  LPWSTR lpNewFileName,
  __in_opt  LPPROGRESS_ROUTINE lpProgressRoutine,
  __in_opt  LPVOID lpData,
  __in      DWORD dwFlags
) {
    BOOL ret = Old_MoveFileWithProgressW(lpExistingFileName, lpNewFileName,
        lpProgressRoutine, lpData, dwFlags);
    LOQ("uu", "ExistingFileName", lpExistingFileName,
        "NewFileName", lpNewFileName);
    return ret;
}

BOOL (WINAPI *Old_DeleteFileW)(
  __in  LPWSTR lpFileName
);

BOOL WINAPI New_DeleteFileW(
  __in  LPWSTR lpFileName
) {
    BOOL ret = Old_DeleteFileW(lpFileName);
    LOQ("u", "FileName", lpFileName);
    return ret;
}
