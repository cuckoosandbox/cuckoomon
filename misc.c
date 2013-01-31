/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2013 Cuckoo Sandbox Developers

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
#include <ctype.h>
#include <shlwapi.h>
#include "ntapi.h"
#include "misc.h"

ULONG_PTR parent_process_id() // By Napalm @ NetCore2K (rohitab.com)
{
    ULONG_PTR pbi[6]; ULONG ulSize = 0;
    LONG (WINAPI *NtQueryInformationProcess)(HANDLE ProcessHandle,
        ULONG ProcessInformationClass, PVOID ProcessInformation,
        ULONG ProcessInformationLength, PULONG ReturnLength);

    *(FARPROC *) &NtQueryInformationProcess = GetProcAddress(
        LoadLibrary("ntdll"), "NtQueryInformationProcess");

    if(NtQueryInformationProcess != NULL && NtQueryInformationProcess(
            GetCurrentProcess(), 0, &pbi, sizeof(pbi), &ulSize) >= 0 &&
            ulSize == sizeof(pbi)) {
        return pbi[5];
    }
    return 0;
}

DWORD pid_from_process_handle(HANDLE process_handle)
{
    PROCESS_BASIC_INFORMATION pbi = {}; ULONG ulSize;
    LONG (WINAPI *NtQueryInformationProcess)(HANDLE ProcessHandle,
        ULONG ProcessInformationClass, PVOID ProcessInformation,
        ULONG ProcessInformationLength, PULONG ReturnLength);

    *(FARPROC *) &NtQueryInformationProcess = GetProcAddress(
        LoadLibrary("ntdll"), "NtQueryInformationProcess");

    if(NtQueryInformationProcess != NULL && NtQueryInformationProcess(
            process_handle, 0, &pbi, sizeof(pbi), &ulSize) >= 0 &&
            ulSize == sizeof(pbi)) {
        return pbi.UniqueProcessId;
    }
    return 0;
}

DWORD pid_from_thread_handle(HANDLE thread_handle)
{
    THREAD_BASIC_INFORMATION tbi = {}; ULONG ulSize;
    LONG (WINAPI *NtQueryInformationThread)(HANDLE ThreadHandle,
        ULONG ThreadInformationClass, PVOID ThreadInformation,
        ULONG ThreadInformationLength, PULONG ReturnLength);

    *(FARPROC *) &NtQueryInformationThread = GetProcAddress(
        LoadLibrary("ntdll"), "NtQueryInformationThread");

    if(NtQueryInformationThread != NULL && NtQueryInformationThread(
            thread_handle, 0, &tbi, sizeof(tbi), &ulSize) >= 0 &&
            ulSize == sizeof(tbi)) {
        return (DWORD) tbi.ClientId.UniqueProcess;
    }
    return 0;
}

DWORD random()
{
    static BOOLEAN (WINAPI *pRtlGenRandom)(PVOID RandomBuffer,
        ULONG RandomBufferLength);

    if(pRtlGenRandom == NULL) {
        *(FARPROC *) &pRtlGenRandom = GetProcAddress(
            GetModuleHandleW(L"advapi32"), "SystemFunction036");
    }

    DWORD ret;
    return pRtlGenRandom(&ret, sizeof(ret)) ? ret : rand();
}

DWORD randint(DWORD min, DWORD max)
{
    return min + (random() % (max - min + 1));
}

BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj)
{
    static NTSTATUS (WINAPI *pNtQueryAttributesFile)(
        _In_   const OBJECT_ATTRIBUTES *ObjectAttributes,
        _Out_  PFILE_BASIC_INFORMATION FileInformation
    );

    if(pNtQueryAttributesFile == NULL) {
        *(FARPROC *) &pNtQueryAttributesFile = GetProcAddress(
            GetModuleHandle("ntdll"), "NtQueryAttributesFile");
    }

    FILE_BASIC_INFORMATION basic_information;
    if(NT_SUCCESS(pNtQueryAttributesFile(obj, &basic_information))) {
        return basic_information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    }
    return FALSE;
}

int path_compare(const wchar_t *a, const wchar_t *b, int len)
{
    for (; len != 0; len--, a++, b++) {
        if((*a == '/' || *a == '\\') && (*b == '/' || *b == '\\')) {
            continue;
        }

        if(towlower(*a) != towlower(*b)) {
            return towlower(*a) < towlower(*b) ? -1 : 1;
        }
    }
    return 0;
}

int path_from_handle(HANDLE directory_handle, wchar_t *path)
{
    static NTSTATUS (WINAPI *pNtQueryVolumeInformationFile)(
        _In_   HANDLE FileHandle,
        _Out_  PIO_STATUS_BLOCK IoStatusBlock,
        _Out_  PVOID FsInformation,
        _In_   ULONG Length,
        _In_   FS_INFORMATION_CLASS FsInformationClass
    );

    if(pNtQueryVolumeInformationFile == NULL) {
        *(FARPROC *) &pNtQueryVolumeInformationFile = GetProcAddress(
            GetModuleHandle("ntdll"), "NtQueryVolumeInformationFile");
    }

    static NTSTATUS (WINAPI *pNtQueryInformationFile)(
        _In_   HANDLE FileHandle,
        _Out_  PIO_STATUS_BLOCK IoStatusBlock,
        _Out_  PVOID FileInformation,
        _In_   ULONG Length,
        _In_   FILE_INFORMATION_CLASS FileInformationClass
    );

    if(pNtQueryInformationFile == NULL) {
        *(FARPROC *) &pNtQueryInformationFile = GetProcAddress(
            GetModuleHandle("ntdll"), "NtQueryInformationFile");
    }

    IO_STATUS_BLOCK status = {};
    FILE_FS_VOLUME_INFORMATION volume_information;

    unsigned char buf[FILE_NAME_INFORMATION_REQUIRED_SIZE];
    FILE_NAME_INFORMATION *name_information = (FILE_NAME_INFORMATION *) buf;

    // get the volume serial number of the directory handle
    if(NT_SUCCESS(pNtQueryVolumeInformationFile(directory_handle, &status,
            &volume_information, sizeof(volume_information),
            FileFsVolumeInformation))) {

        unsigned long serial_number;

        // enumerate all harddisks in order to find the corresponding serial
        // number
        wcscpy(path, L"?:\\");
        for (char ch = 'A'; ch <= 'Z'; ch++) {
            path[0] = ch;
            if(GetVolumeInformationW(path, NULL, 0, &serial_number, NULL,
                    NULL, NULL, 0) &&
                    serial_number == volume_information.VolumeSerialNumber) {

                // obtain the relative path for this filename on the given
                // harddisk
                if(NT_SUCCESS(pNtQueryInformationFile(directory_handle,
                        &status, name_information,
                        FILE_NAME_INFORMATION_REQUIRED_SIZE,
                        FileNameInformation))) {

                    int length =
                        name_information->FileNameLength / sizeof(wchar_t);

                    // NtQueryInformationFile omits the "C:" part in a
                    // filename, apparently
                    wcsncpy(path + 2, name_information->FileName, length);
                    path[2 + length] = 0;
                    return 2 + length;
                }
            }
        }

    }
    return 0;
}

int path_from_object_attributes(const OBJECT_ATTRIBUTES *obj, wchar_t *path)
{
    if(obj->RootDirectory == NULL) {
        wcsncpy(path, obj->ObjectName->Buffer, obj->ObjectName->Length);
        path[obj->ObjectName->Length / sizeof(wchar_t)] = 0;
        return obj->ObjectName->Length / sizeof(wchar_t);
    }

    int len = path_from_handle(obj->RootDirectory, path);
    path[len++] = '\\';
    wcsncpy(&path[len], obj->ObjectName->Buffer,
        obj->ObjectName->Length / sizeof(wchar_t));
    path[len + obj->ObjectName->Length / sizeof(wchar_t)] = 0;
    return len + obj->ObjectName->Length / sizeof(wchar_t);
}
