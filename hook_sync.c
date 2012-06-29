#include <stdio.h>
#include <windows.h>
#include "ntapi.h"
#include "log.h"

NTSTATUS (WINAPI *Old_NtCreateMutant)(
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        BOOLEAN InitialOwner
);

NTSTATUS WINAPI New_NtCreateMutant(
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in_opt    POBJECT_ATTRIBUTES ObjectAttributes,
    __in        BOOLEAN InitialOwner
) {
    NTSTATUS ret = Old_NtCreateMutant(MutantHandle, DesiredAccess,
        ObjectAttributes, InitialOwner);
    LOQ("lOl", "Handle", *MutantHandle, "MutexName", ObjectAttributes,
        "InitialOwner", InitialOwner);
    return ret;
}

NTSTATUS (WINAPI *Old_NtOpenMutant)(
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in        POBJECT_ATTRIBUTES ObjectAttributes
);

NTSTATUS WINAPI New_NtOpenMutant(
    __out       PHANDLE MutantHandle,
    __in        ACCESS_MASK DesiredAccess,
    __in        POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS ret = Old_NtOpenMutant(MutantHandle, DesiredAccess,
        ObjectAttributes);
    LOQ("lO", "Handle", *MutantHandle, "MutexName", ObjectAttributes);
    return ret;
}
