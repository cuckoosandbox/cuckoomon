#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"

HOOKDEF(HWND, WINAPI, FindWindowA,
  __in_opt  LPCTSTR lpClassName,
  __in_opt  LPCTSTR lpWindowName
) {
    HWND ret = Old_FindWindowA(lpClassName, lpWindowName);
    LOQ("ss", "ClassName", lpClassName, "WindowName", lpWindowName);
    return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowW,
  __in_opt  LPWSTR lpClassName,
  __in_opt  LPWSTR lpWindowName
) {
    HWND ret = Old_FindWindowW(lpClassName, lpWindowName);
    LOQ("uu", "ClassName", lpClassName, "WindowName", lpWindowName);
    return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExA,
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPCTSTR lpszClass,
  __in_opt  LPCTSTR lpszWindow
) {
    HWND ret = Old_FindWindowExA(hwndParent, hwndChildAfter, lpszClass,
        lpszWindow);

    // lpszClass can be one of the predefined window controls.. which lay in
    // the 0..ffff range
    if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
        LOQ("ls", "ClassName", lpszClass, "WindowName", lpszWindow);
    }
    else {
        LOQ("ss", "ClassName", lpszClass, "WindowName", lpszWindow);
    }
    return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowExW,
  __in_opt  HWND hwndParent,
  __in_opt  HWND hwndChildAfter,
  __in_opt  LPWSTR lpszClass,
  __in_opt  LPWSTR lpszWindow
) {
    HWND ret = Old_FindWindowExW(hwndParent, hwndChildAfter, lpszClass,
        lpszWindow);
    // lpszClass can be one of the predefined window controls.. which lay in
    // the 0..ffff range
    if(((DWORD_PTR) lpszClass & 0xffff) == (DWORD_PTR) lpszClass) {
        LOQ("lu", "ClassName", lpszClass, "WindowName", lpszWindow);
    }
    else {
        LOQ("uu", "ClassName", lpszClass, "WindowName", lpszWindow);
    }
    return ret;
}
