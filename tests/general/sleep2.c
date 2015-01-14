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
    LoadLibrary( _T("../../cuckoomon.dll"));

    unsigned int start = GetTickCount();
    printf("%d\n", start);

    Sleep(1000);

    printf("%d -> %d\n", GetTickCount(), GetTickCount() - start);

    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 0xfffffff; j++);
    }

    printf("%d -> %d\n", GetTickCount(), GetTickCount() - start);

    Sleep(1000);

    printf("%d -> %d\n", GetTickCount(), GetTickCount() - start);

	return 0;
}
