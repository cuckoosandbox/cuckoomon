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
#include <windns.h>
#include <wininet.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"
#include "pipe.h"

static IS_SUCCESS_HINTERNET();

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
    if(ret == S_OK) {
        pipe("FILE_NEW:%S", szFileName);
    }
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenA,
    _In_  LPCTSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPCTSTR lpszProxyName,
    _In_  LPCTSTR lpszProxyBypass,
    _In_  DWORD dwFlags
) {
    HINTERNET ret = Old_InternetOpenA(lpszAgent, dwAccessType, lpszProxyName,
        lpszProxyBypass, dwFlags);
    LOQ("spssp", "Agent", lpszAgent, "AccessType", dwAccessType,
        "ProxyName", lpszProxyName, "ProxyBypass", lpszProxyBypass,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenW,
    _In_  LPWSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPWSTR lpszProxyName,
    _In_  LPWSTR lpszProxyBypass,
    _In_  DWORD dwFlags
) {
    HINTERNET ret = Old_InternetOpenW(lpszAgent, dwAccessType, lpszProxyName,
        lpszProxyBypass, dwFlags);
    LOQ("upuup", "Agent", lpszAgent, "AccessType", dwAccessType,
        "ProxyName", lpszProxyName, "ProxyBypass", lpszProxyBypass,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetConnectA,
    _In_  HINTERNET hInternet,
    _In_  LPCTSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPCTSTR lpszUsername,
    _In_  LPCTSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetConnectA(hInternet, lpszServerName,
        nServerPort, lpszUsername, lpszPassword, dwService, dwFlags,
        dwContext);
    LOQ("pslsslp", "InternetHandle", hInternet, "ServerName", lpszServerName,
        "ServerPort", nServerPort, "Username", lpszUsername,
        "Password", lpszPassword, "Service", dwService, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetConnectW,
    _In_  HINTERNET hInternet,
    _In_  LPWSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPWSTR lpszUsername,
    _In_  LPWSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetConnectW(hInternet, lpszServerName,
        nServerPort, lpszUsername, lpszPassword, dwService, dwFlags,
        dwContext);
    LOQ("puluulp", "InternetHandle", hInternet, "ServerName", lpszServerName,
        "ServerPort", nServerPort, "Username", lpszUsername,
        "Password", lpszPassword, "Service", dwService, "Flags", dwFlags);
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
    LOQ("psSp", "ConnectionHandle", hInternet, "URL", lpszUrl,
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
    LOQ("puUp", "ConnectionHandle", hInternet, "URL", lpszUrl,
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

HOOKDEF(BOOL, WINAPI, InternetReadFile,
    _In_   HINTERNET hFile,
    _Out_  LPVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToRead,
    _Out_  LPDWORD lpdwNumberOfBytesRead
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead,
        lpdwNumberOfBytesRead);
    LOQ("pB", "InternetHandle", hFile,
        "Buffer", lpdwNumberOfBytesRead, lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetWriteFile,
    _In_   HINTERNET hFile,
    _In_   LPCVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToWrite,
    _Out_  LPDWORD lpdwNumberOfBytesWritten
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_InternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite,
        lpdwNumberOfBytesWritten);
    LOQ("pB", "InternetHandle", hFile,
        "Buffer", lpdwNumberOfBytesWritten, lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetCloseHandle,
    _In_  HINTERNET hInternet
) {
    IS_SUCCESS_BOOL();

    BOOL ret = Old_InternetCloseHandle(hInternet);
    LOQ("p", "InternetHandle", hInternet);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_A,
    __in         PCSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    IS_SUCCESS_ZERO();

    DNS_STATUS ret = Old_DnsQuery_A(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);
    LOQ("sil", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_UTF8,
    __in         LPBYTE lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    IS_SUCCESS_ZERO();

    DNS_STATUS ret = Old_DnsQuery_UTF8(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);
    LOQ("sil", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_W,
    __in         PWSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    IS_SUCCESS_ZERO();

    DNS_STATUS ret = Old_DnsQuery_W(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);
    LOQ("uil", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(int, WSAAPI, getaddrinfo,
    _In_opt_  PCSTR pNodeName,
    _In_opt_  PCSTR pServiceName,
    _In_opt_  const ADDRINFOA *pHints,
    _Out_     PADDRINFOA *ppResult
) {
    IS_SUCCESS_ZERO();

    BOOL ret = Old_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    LOQ("ss", "NodeName", pNodeName, "ServiceName", pServiceName);
    return ret;
}

HOOKDEF(int, WSAAPI, GetAddrInfoW,
    _In_opt_  PCWSTR pNodeName,
    _In_opt_  PCWSTR pServiceName,
    _In_opt_  const ADDRINFOW *pHints,
    _Out_     PADDRINFOW *ppResult
) {
    IS_SUCCESS_ZERO();

    BOOL ret = Old_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    LOQ("uu", "NodeName", pNodeName, "ServiceName", pServiceName);
    return ret;
}
