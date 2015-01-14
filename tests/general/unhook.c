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
#include <tchar.h>

int main(void)
{
    FARPROC fp = GetProcAddress(
        GetModuleHandle( _T( "kernel32" ) ), "IsDebuggerPresent");

	if ( fp == NULL )
	{
		fprintf( stderr, "Error getprocaddress isdebuggerpresent" );
		return 1;
	}

    unsigned long old_protect;
    if ( VirtualProtect(fp, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect) == 0 )
	{
		fprintf( stderr, "Error VirtualProtect isdebuggerpresent" );
		return 1;
	}

    // Corrupt the hook.
    memset(fp, 0xcc, 32);

    fp = GetProcAddress(GetModuleHandle(_T("kernel32")), "CopyFileA");
	if ( fp == NULL )
	{
		fprintf( stderr, "Error getprocaddress CopyFileA" );
		return 1;
	}

	if ( VirtualProtect(fp, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect) == 0 )
	{
		fprintf( stderr, "Error VirtualProtect CopyFileA" );
		return 1;
	}

    // Restore the hook.
    memcpy(fp, "\x8b\xff\x55\x8b\xec", 5);

    Sleep(10000);

	return 0;
}
