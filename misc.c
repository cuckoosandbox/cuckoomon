#include <stdio.h>
#include <windows.h>
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
