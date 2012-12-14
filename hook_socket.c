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
#include <winsock2.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"

static IS_SUCCESS_ZERO();
static const char *module_name = "socket";

HOOKDEF(int, WINAPI, WSAStartup,
    _In_   WORD wVersionRequested,
    _Out_  LPWSADATA lpWSAData
) {
    int ret = Old_WSAStartup(wVersionRequested, lpWSAData);
    LOQ("p", "VersionRequested", wVersionRequested);
    return ret;
}
