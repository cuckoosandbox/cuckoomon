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
#include "pipe.h"

void pipe_write(const char *fmt, ...)
{
    va_list args; char buf[2048]; HANDLE pipe_handle; DWORD length;

    va_start(args, fmt);
    length = vsnprintf(buf, sizeof(buf), fmt, args);

    while ((pipe_handle = CreateFile(PIPE_NAME, GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) {
        if(GetLastError() == ERROR_PIPE_BUSY || !WaitNamedPipe(PIPE_NAME,
                20000)) {
            return;
        }
    }

    WriteFile(pipe_handle, buf, length, &length, NULL);
    CloseHandle(pipe_handle);

    va_end(args);
}

void pipe_write_read(char *out, int *outlen, const char *fmt, ...)
{
    va_list args; char buf[2048]; HANDLE pipe_handle; DWORD length;

    va_start(args, fmt);
    length = vsnprintf(buf, sizeof(buf), fmt, args);

    while ((pipe_handle = CreateFile(PIPE_NAME, GENERIC_WRITE | GENERIC_READ,
            0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) {
        if(GetLastError() == ERROR_PIPE_BUSY || !WaitNamedPipe(PIPE_NAME,
                20000)) {
            return;
        }
    }

    WriteFile(pipe_handle, buf, length, &length, NULL);
    ReadFile(pipe_handle, out, *outlen, (DWORD *) outlen, NULL);
    CloseHandle(pipe_handle);

    va_end(args);
}

