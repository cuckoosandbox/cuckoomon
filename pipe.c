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
    va_list args; char buf[2048]; DWORD length;

    va_start(args, fmt);
    length = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    CallNamedPipe(PIPE_NAME, buf, length, buf, sizeof(buf), &length, 0);
}

void pipe_write_read(char *out, int *outlen, const char *fmt, ...)
{
    va_list args; char buf[2048]; DWORD length;

    va_start(args, fmt);
    length = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    CallNamedPipe(PIPE_NAME, buf, length, out, *outlen, (DWORD *) outlen, 0);
}

