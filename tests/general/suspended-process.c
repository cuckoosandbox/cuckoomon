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

int main(int argc, char *argv[])
{
    if(argc != 1) {
        printf("arg: %s\n", argv[1]);
        fflush(stdout);
        return 1;
    }

    STARTUPINFO si = {sizeof(si)}; 
	PROCESS_INFORMATION pi; 
	char buf[256];

    sprintf(buf, "\"%s\" a", argv[0]);

    BOOL ret = CreateProcess(argv[0], buf, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    printf("ret: %d\n", ret);
    fflush(stdout);

	if ( ret == 0 )
	{
		fprintf( stderr, "Error CreateProcess" );
		return 1;
	}

    if ( ResumeThread(pi.hThread) ==  -1 )
	{
		fprintf( stderr, "Error ResumeThread" );
		return 1;
	}

    WaitForSingleObject(pi.hThread, INFINITE);
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code;
    if ( GetExitCodeProcess(pi.hProcess, &exit_code) == 0 )
	{
		fprintf( stderr, "Error GetExitCodeProcess" );
		return 1;
	}
    printf("ret: %d\n", exit_code);
    fflush(stdout);

	return 0;
}
