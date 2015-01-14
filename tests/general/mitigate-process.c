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

/* multiple ways to inject into another process */

int main(int argc, char *argv[])
{
    if(argc == 2) {
        printf("Child process %s.. exiting..\n", argv[1]);
        ExitProcess(0);
    }

    char buf[256];

    // WinExec
    sprintf(buf, "\"%s\" a", argv[0]);
    if ( WinExec(buf, SW_SHOW) <= 31 )
	{
		fprintf( stderr, "Error WinExec" );
		return 1;
	}

    // ShellExecute
    if ( ShellExecuteA(NULL, NULL, argv[0], "b", NULL, SW_SHOW) <= 32 )
	{
		fprintf( stderr, "Error ShellExecute" );
		return 1;
	}

    // CreateProcess
    sprintf(buf, "\"%s\" c", argv[0]);
    STARTUPINFO si = {sizeof(si)}; PROCESS_INFORMATION pi = {};
    if ( CreateProcessA(NULL, buf, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) == 0 )
	{
		fprintf( stderr, "Error CreateProcessA");
		return 1;
	}

    // system
    sprintf(buf, "\"%s\" d", argv[0]);
    if ( system(buf) == -1 )
	{
		fprintf( stderr, "Error system");
		return 1;
	}

    return 0;
}
