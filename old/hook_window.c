/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

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

static IS_SUCCESS_HWND();

HOOKDEF(HWND, WINAPI, FindWindowA,
    __in_opt  LPCTSTR lpClassName,
    __in_opt  LPCTSTR lpWindowName
) {
    // The atom must be in the low-order word of lpClassName;
    // the high-order word must be zero (from MSDN documentation.)
    HWND ret = Old_FindWindowA(lpClassName, lpWindowName);
    if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
        LOQ("ls", "ClassName", lpClassName, "WindowName", lpWindowName);
    }
    else {
        LOQ("ss", "ClassName", lpClassName, "WindowName", lpWindowName);
    }
    return ret;
}

HOOKDEF(HWND, WINAPI, FindWindowW,
    __in_opt  LPWSTR lpClassName,
    __in_opt  LPWSTR lpWindowName
) {
    HWND ret = Old_FindWindowW(lpClassName, lpWindowName);
    if(((DWORD_PTR) lpClassName & 0xffff) == (DWORD_PTR) lpClassName) {
        LOQ("lu", "ClassName", lpClassName, "WindowName", lpWindowName);
    }
    else {
        LOQ("uu", "ClassName", lpClassName, "WindowName", lpWindowName);
    }
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
        LOQ2("ss", "ClassName", lpszClass, "WindowName", lpszWindow);
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
        LOQ2("uu", "ClassName", lpszClass, "WindowName", lpszWindow);
    }
    return ret;
}
