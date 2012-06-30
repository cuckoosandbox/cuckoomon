#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"

HOOKDEF(NTSTATUS, WINAPI, NtCreateMutant,
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        BOOLEAN InitialOwner
) {
    NTSTATUS ret = Old_NtCreateMutant(MutantHandle, DesiredAccess,
        ObjectAttributes, InitialOwner);
    LOQ("POl", "Handle", MutantHandle, "MutexName", ObjectAttributes,
        "InitialOwner", InitialOwner);
    return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtOpenMutant,
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in        POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS ret = Old_NtOpenMutant(MutantHandle, DesiredAccess,
        ObjectAttributes);
    LOQ("PO", "Handle", MutantHandle, "MutexName", ObjectAttributes);
    return ret;
}
