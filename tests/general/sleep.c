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

DWORD WINAPI thread(LPVOID lpNothing)
{
    return 0;
}

int main(void)
{
    LoadLibrary(_T("../../cuckoomon.dll"));

    // sleep for five seconds (skipped)
    for (int i = 0; i < 100; i++) {
        Sleep(50);

        printf("tick: %ld\n", GetTickCount());
    }

    // sleep for 10 seconds (skipped)
    Sleep(10000);

    printf("tick: %ld\n", GetTickCount());

    printf("starting second thread\n");
    CloseHandle(CreateThread(NULL, 0, &thread, NULL, 0, NULL));

    // sleep for 5 seconds (not skipped)
    Sleep(5000);

	return 0;
}
