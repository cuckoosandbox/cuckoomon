#include <stdio.h>
#include <windows.h>
#include "ntapi.h"
#include "log.h"

#define LOQ(fmt, ...) loq("sl" # fmt, "function", &__FUNCTION__[4], \
    "return", ret, ##__VA_ARGS__)

LONG (WINAPI *Old_RegOpenKeyExA)(
  __in        HKEY hKey,
  __in_opt    LPCTSTR lpSubKey,
  __reserved  DWORD ulOptions,
  __in        REGSAM samDesired,
  __out       PHKEY phkResult
);

LONG WINAPI New_RegOpenKeyExA(
  __in        HKEY hKey,
  __in_opt    LPCTSTR lpSubKey,
  __reserved  DWORD ulOptions,
  __in        REGSAM samDesired,
  __out       PHKEY phkResult
) {
    LONG ret = Old_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired,
        phkResult);
    LOQ("lsl", "Registry", hKey, "SubKey", lpSubKey, "Handle", *phkResult);
    return ret;
}

LONG (WINAPI *Old_RegOpenKeyExW)(
  __in        HKEY hKey,
  __in_opt    LPWSTR lpSubKey,
  __reserved  DWORD ulOptions,
  __in        REGSAM samDesired,
  __out       PHKEY phkResult
);

LONG WINAPI New_RegOpenKeyExW(
  __in        HKEY hKey,
  __in_opt    LPWSTR lpSubKey,
  __reserved  DWORD ulOptions,
  __in        REGSAM samDesired,
  __out       PHKEY phkResult
) {
    LONG ret = Old_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired,
        phkResult);
    LOQ("lul", "Registry", hKey, "SubKey", lpSubKey, "Handle", *phkResult);
    return ret;
}

LONG (WINAPI *Old_RegCreateKeyExA)(
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

LONG WINAPI New_RegCreateKeyExA(
  __in        HKEY hKey,
  __in        LPCTSTR lpSubKey,
  __reserved  DWORD Reserved,
  __in_opt    LPTSTR lpClass,
  __in        DWORD dwOptions,
  __in        REGSAM samDesired,
  __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __out       PHKEY phkResult,
  __out_opt   LPDWORD lpdwDisposition
) {
    LONG ret = Old_RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass,
        dwOptions, samDesired, lpSecurityAttributes, phkResult,
        lpdwDisposition);
    LOQ("lssll", "Registry", hKey, "SubKey", lpSubKey, "Class", lpClass,
        "Access", samDesired, "Handle", *phkResult);
    return ret;
}

LONG (WINAPI *Old_RegCreateKeyExW)(
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

LONG WINAPI New_RegCreateKeyExW(
  __in        HKEY hKey,
  __in        LPWSTR lpSubKey,
  __reserved  DWORD Reserved,
  __in_opt    LPWSTR lpClass,
  __in        DWORD dwOptions,
  __in        REGSAM samDesired,
  __in_opt    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  __out       PHKEY phkResult,
  __out_opt   LPDWORD lpdwDisposition
) {
    LONG ret = Old_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass,
        dwOptions, samDesired, lpSecurityAttributes, phkResult,
        lpdwDisposition);
    LOQ("luull", "Registry", hKey, "SubKey", lpSubKey, "Class", lpClass,
        "Access", samDesired, "Handle", *phkResult);
    return ret;
}

LONG (WINAPI *Old_RegDeleteKeyA)(
  __in  HKEY hKey,
  __in  LPCTSTR lpSubKey
);

LONG WINAPI New_RegDeleteKeyA(
  __in  HKEY hKey,
  __in  LPCTSTR lpSubKey
) {
    LONG ret = Old_RegDeleteKeyA(hKey, lpSubKey);
    LOQ("ls", "Handle", hKey, "SubKey", lpSubKey);
    return ret;
}

LONG (WINAPI *Old_RegDeleteKeyW)(
  __in  HKEY hKey,
  __in  LPWSTR lpSubKey
);

LONG WINAPI New_RegDeleteKeyW(
  __in  HKEY hKey,
  __in  LPWSTR lpSubKey
) {
    LONG ret = Old_RegDeleteKeyW(hKey, lpSubKey);
    LOQ("lu", "Handle", hKey, "SubKey", lpSubKey);
    return ret;
}

LONG (WINAPI *Old_RegEnumKeyW)(
  __in   HKEY hKey,
  __in   DWORD dwIndex,
  __out  LPWSTR lpName,
  __in   DWORD cchName
);

LONG WINAPI New_RegEnumKeyW(
  __in   HKEY hKey,
  __in   DWORD dwIndex,
  __out  LPWSTR lpName,
  __in   DWORD cchName
) {
    LONG ret = Old_RegEnumKeyW(hKey, dwIndex, lpName, cchName);
    LOQ("llu", "Handle", hKey, "Index", dwIndex, "Name", lpName);
    return ret;
}

LONG (WINAPI *Old_RegEnumKeyExA)(
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPTSTR lpName,
  __inout      LPDWORD lpcName,
  __reserved   LPDWORD lpReserved,
  __inout      LPTSTR lpClass,
  __inout_opt  LPDWORD lpcClass,
  __out_opt    PFILETIME lpftLastWriteTime
);

LONG WINAPI New_RegEnumKeyExA(
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPTSTR lpName,
  __inout      LPDWORD lpcName,
  __reserved   LPDWORD lpReserved,
  __inout      LPTSTR lpClass,
  __inout_opt  LPDWORD lpcClass,
  __out_opt    PFILETIME lpftLastWriteTime
) {
    LONG ret = Old_RegEnumKeyExA(hKey, dwIndex, lpName, lpcName, lpReserved,
        lpClass, lpcClass, lpftLastWriteTime);
    LOQ("llss", "Handle", hKey, "Index", dwIndex, "Name", lpName,
        "Class", lpClass);
    return ret;
}

LONG (WINAPI *Old_RegEnumKeyExW)(
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPWSTR lpName,
  __inout      LPDWORD lpcName,
  __reserved   LPDWORD lpReserved,
  __inout      LPWSTR lpClass,
  __inout_opt  LPDWORD lpcClass,
  __out_opt    PFILETIME lpftLastWriteTime
);

LONG WINAPI New_RegEnumKeyExW(
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPWSTR lpName,
  __inout      LPDWORD lpcName,
  __reserved   LPDWORD lpReserved,
  __inout      LPWSTR lpClass,
  __inout_opt  LPDWORD lpcClass,
  __out_opt    PFILETIME lpftLastWriteTime
) {
    LONG ret = Old_RegEnumKeyExW(hKey, dwIndex, lpName, lpcName, lpReserved,
        lpClass, lpcClass, lpftLastWriteTime);
    LOQ("lluu", "Handle", hKey, "Index", dwIndex, "Name", lpName,
        "Class", lpClass);
    return ret;
}

LONG (WINAPI *Old_RegEnumValueA)(
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPTSTR lpValueName,
  __inout      LPDWORD lpcchValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

LONG WINAPI New_RegEnumValueA(
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPTSTR lpValueName,
  __inout      LPDWORD lpcchValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
) {
    LONG ret = Old_RegEnumValueA(hKey, dwIndex, lpValueName, lpcchValueName,
        lpReserved, lpType, lpData, lpcbData);
    LOQ("llsb", "Handle", hKey, "Index", dwIndex, "ValueName", lpValueName,
        "Data", lpcbData ? *lpcbData : 0, lpData);
    return ret;
}

LONG (WINAPI *Old_RegEnumValueW)(
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPWSTR lpValueName,
  __inout      LPDWORD lpcchValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

LONG WINAPI New_RegEnumValueW(
  __in         HKEY hKey,
  __in         DWORD dwIndex,
  __out        LPWSTR lpValueName,
  __inout      LPDWORD lpcchValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
) {
    LONG ret = Old_RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName,
        lpReserved, lpType, lpData, lpcbData);
    LOQ("llub", "Handle", hKey, "Index", dwIndex, "ValueName", lpValueName,
        "Data", lpcbData ? *lpcbData : 0, lpData);
    return ret;
}

LONG (WINAPI *Old_RegSetValueExA)(
  __in        HKEY hKey,
  __in_opt    LPCTSTR lpValueName,
  __reserved  DWORD Reserved,
  __in        DWORD dwType,
  __in        const BYTE *lpData,
  __in        DWORD cbData
);

LONG WINAPI New_RegSetValueExA(
  __in        HKEY hKey,
  __in_opt    LPCTSTR lpValueName,
  __reserved  DWORD Reserved,
  __in        DWORD dwType,
  __in        const BYTE *lpData,
  __in        DWORD cbData
) {
    LONG ret = Old_RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData,
        cbData);
    LOQ("lslb", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
        "Buffer", cbData, lpData);
    return ret;
}

LONG (WINAPI *Old_RegSetValueExW)(
  __in        HKEY hKey,
  __in_opt    LPWSTR lpValueName,
  __reserved  DWORD Reserved,
  __in        DWORD dwType,
  __in        const BYTE *lpData,
  __in        DWORD cbData
);

LONG WINAPI New_RegSetValueExW(
  __in        HKEY hKey,
  __in_opt    LPWSTR lpValueName,
  __reserved  DWORD Reserved,
  __in        DWORD dwType,
  __in        const BYTE *lpData,
  __in        DWORD cbData
) {
    LONG ret = Old_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData,
        cbData);
    LOQ("lulb", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
        "Buffer", cbData, lpData);
    return ret;
}

LONG (WINAPI *Old_RegQueryValueExA)(
  __in         HKEY hKey,
  __in_opt     LPCTSTR lpValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

LONG WINAPI New_RegQueryValueExA(
  __in         HKEY hKey,
  __in_opt     LPCTSTR lpValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
) {
    LONG ret = Old_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType,
        lpData, lpcbData);
    LOQ("lslb", "Handle", hKey, "ValueName", lpValueName,
        "Type", lpType ? *lpType : 0,
        "Buffer", lpcbData ? *lpcbData : 0, lpData);
    return ret;
}

LONG (WINAPI *Old_RegQueryValueExW)(
  __in         HKEY hKey,
  __in_opt     LPWSTR lpValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
);

LONG WINAPI New_RegQueryValueExW(
  __in         HKEY hKey,
  __in_opt     LPWSTR lpValueName,
  __reserved   LPDWORD lpReserved,
  __out_opt    LPDWORD lpType,
  __out_opt    LPBYTE lpData,
  __inout_opt  LPDWORD lpcbData
) {
    LONG ret = Old_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType,
        lpData, lpcbData);
    LOQ("lulb", "Handle", hKey, "ValueName", lpValueName,
        "Type", lpType ? *lpType : 0,
        "Buffer", lpcbData ? *lpcbData : 0, lpData);
    return ret;
}

LONG (WINAPI *Old_RegDeleteValueA)(
  __in      HKEY hKey,
  __in_opt  LPCTSTR lpValueName
);

LONG WINAPI New_RegDeleteValueA(
  __in      HKEY hKey,
  __in_opt  LPCTSTR lpValueName
) {
    LONG ret = Old_RegDeleteValueA(hKey, lpValueName);
    LOQ("ls", "Handle", hKey, "ValueName", lpValueName);
    return ret;
}

LONG (WINAPI *Old_RegDeleteValueW)(
  __in      HKEY hKey,
  __in_opt  LPWSTR lpValueName
);

LONG WINAPI New_RegDeleteValueW(
  __in      HKEY hKey,
  __in_opt  LPWSTR lpValueName
) {
    LONG ret = Old_RegDeleteValueW(hKey, lpValueName);
    LOQ("lu", "Handle", hKey, "ValueName", lpValueName);
    return ret;
}
