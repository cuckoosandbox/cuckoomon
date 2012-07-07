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

static IS_SUCCESS_HINTERNET();
static const char *module_name = "network";

HOOKDEF(HRESULT, WINAPI, URLDownloadToFileW,
    LPUNKNOWN pCaller,
    LPWSTR szURL,
    LPWSTR szFileName,
    DWORD dwReserved,
    LPVOID lpfnCB
) {
    IS_SUCCESS_HRESULT();

    HRESULT ret = Old_URLDownloadToFileW(pCaller, szURL, szFileName,
        dwReserved, lpfnCB);
    LOQ("uu", "URL", szURL, "FileName", szFileName);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlA,
  __in  HINTERNET hInternet,
  __in  LPCTSTR lpszUrl,
  __in  LPCTSTR lpszHeaders,
  __in  DWORD dwHeadersLength,
  __in  DWORD dwFlags,
  __in  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders,
        dwHeadersLength, dwFlags, dwContext);
    if(dwHeadersLength == (DWORD) -1) dwHeadersLength = strlen(lpszHeaders);
    LOQ("psSl", "ConnectionHandle", hInternet, "URL", lpszUrl,
        "Headers", dwHeadersLength, lpszHeaders, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlW,
  __in  HINTERNET hInternet,
  __in  LPWSTR lpszUrl,
  __in  LPWSTR lpszHeaders,
  __in  DWORD dwHeadersLength,
  __in  DWORD dwFlags,
  __in  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders,
        dwHeadersLength, dwFlags, dwContext);
    LOQ("psSl", "ConnectionHandle", hInternet, "URL", lpszUrl,
        "Headers", dwHeadersLength, lpszHeaders, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestA,
  __in  HINTERNET hConnect,
  __in  LPCTSTR lpszVerb,
  __in  LPCTSTR lpszObjectName,
  __in  LPCTSTR lpszVersion,
  __in  LPCTSTR lpszReferer,
  __in  LPCTSTR *lplpszAcceptTypes,
  __in  DWORD dwFlags,
  __in  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName,
        lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    LOQ("psl", "InternetHandle", hConnect, "Path", lpszObjectName,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestW,
  __in  HINTERNET hConnect,
  __in  LPWSTR lpszVerb,
  __in  LPWSTR lpszObjectName,
  __in  LPWSTR lpszVersion,
  __in  LPWSTR lpszReferer,
  __in  LPWSTR *lplpszAcceptTypes,
  __in  DWORD dwFlags,
  __in  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName,
        lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    LOQ("pul", "InternetHandle", hConnect, "Path", lpszObjectName,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestA,
  __in  HINTERNET hRequest,
  __in  LPCTSTR lpszHeaders,
  __in  DWORD dwHeadersLength,
  __in  LPVOID lpOptional,
  __in  DWORD dwOptionalLength
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength);
    if(dwHeadersLength == (DWORD) -1) dwHeadersLength = strlen(lpszHeaders);
    LOQ("pSb", "RequestHandle", hRequest,
        "Headers", dwHeadersLength, lpszHeaders,
        "PostData", dwOptionalLength, lpOptional);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestW,
  __in  HINTERNET hRequest,
  __in  LPWSTR lpszHeaders,
  __in  DWORD dwHeadersLength,
  __in  LPVOID lpOptional,
  __in  DWORD dwOptionalLength
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength);
    LOQ("pUb", "RequestHandle", hRequest,
        "Headers", dwHeadersLength, lpszHeaders,
        "PostData", dwOptionalLength, lpOptional);
    return ret;
}
