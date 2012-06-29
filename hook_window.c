#include <stdio.h>
#include <windows.h>
#include "ntapi.h"
#include "log.h"

HWND (WINAPI *Old_FindWindowA)(
  __in_opt  LPCTSTR lpClassName,
  __in_opt  LPCTSTR lpWindowName
);

HWND WINAPI New_FindWindowA(
  __in_opt  LPCTSTR lpClassName,
  __in_opt  LPCTSTR lpWindowName
) {
    HWND ret = Old_FindWindowA(lpClassName, lpWindowName);
    LOQ("ss", "ClassName", lpClassName, "WindowName", lpWindowName);
    return ret;
}

HWND (WINAPI *Old_FindWindowW)(
  __in_opt  LPWSTR lpClassName,
  __in_opt  LPWSTR lpWindowName
);

HWND WINAPI New_FindWindowW(
  __in_opt  LPWSTR lpClassName,
  __in_opt  LPWSTR lpWindowName
) {
    HWND ret = Old_FindWindowW(lpClassName, lpWindowName);
    LOQ("uu", "ClassName", lpClassName, "WindowName", lpWindowName);
    return ret;
}

HWND (WINAPI *Old_FindWindowExA)(
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPCTSTR lpszClass,
  __in_opt  LPCTSTR lpszWindow
);

HWND WINAPI New_FindWindowExA(
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPCTSTR lpszClass,
  __in_opt  LPCTSTR lpszWindow
) {
    HWND ret = Old_FindWindowExA(hwndParent, hwndChildAfter, lpszClass,
        lpszWindow);
    LOQ("ss", "ClassName", lpszClass, "WindowName", lpszWindow);
    return ret;
}

HWND (WINAPI *Old_FindWindowExW)(
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPWSTR lpszClass,
  __in_opt  LPWSTR lpszWindow
);

HWND WINAPI New_FindWindowExW(
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPWSTR lpszClass,
  __in_opt  LPWSTR lpszWindow
) {
    HWND ret = Old_FindWindowExW(hwndParent, hwndChildAfter, lpszClass,
        lpszWindow);
    LOQ("uu", "ClassName", lpszClass, "WindowName", lpszWindow);
    return ret;
}
