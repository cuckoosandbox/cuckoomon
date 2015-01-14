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
#include <direct.h>
#include <tchar.h>

DWORD WINAPI dummy(LPVOID lpValue)
{
    printf("dummy here!\n");
    return 0;
}

int main(void)
{
    // there we go
    if ( LoadLibrary(_T("../../cuckoomon.dll")) == NULL )
	{
		fprintf( stderr, "Error Loadlibrary cuckoomon" );
		return 1;
	}

    FILE *fp = fopen("test-hello", "r");
    if(fp != NULL) 
		fclose(fp);
	else
	{
		fprintf( stderr, "Error fopen r" );
		return 1;
	}

    fp = fopen("test-hello", "wb");
	if(fp != NULL)
	{
		if ( fwrite("whatsup", 1, 6, fp) != 1 )
		{
			fprintf( stderr, "Error fwrite whatsup" );
			return 1;
		}
		fclose(fp);
	}
	else
	{
		fprintf( stderr, "Error fopen wb" );
		return 1;
	}

    fp = fopen("test-hello", "rb");
	if(fp == NULL)
	{
		fprintf( stderr, "Error fopen rb" );
		return 1;
	}

    char buf[6];
    if ( fread(buf, 1, 6, fp) != 1 )
	{
		fprintf( stderr, "Error fread rb" );
		return 1;
	}
    fclose(fp);

    if ( _mkdir("abc") == -1 )
	{
		fprintf( stderr, "Error mkdir abc" );
		return 1;
	}

    if ( DeleteFile(_T("test-hello")) == 0 )
	{
		fprintf( stderr, "Error Deletefile test-hello" );
		return 1;
	}

    HKEY hKey;
    if(RegCreateKeyEx(HKEY_CURRENT_USER,
            _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, NULL, 0,
            KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        if ( RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL) != ERROR_SUCCESS )
		{
			fprintf( stderr, "Error RegQueryInfoKey" );
			return 1;
		}
        if ( RegSetValueEx(hKey, _T("TestApiHooks"), 0, REG_SZ, (BYTE *) _T("Hoi"), 3) != ERROR_SUCCESS ) 
		{
			fprintf( stderr, "Error RegSetValueEx TestApiHooks" );
			return 1;
		}
        if ( RegDeleteValue(hKey, _T("TestApiHooks")) != ERROR_SUCCESS )
		{
			fprintf( stderr, "Error RegDeleteValue TestApiHooks" );
			return 1;
		}
        RegCloseKey(hKey);
    }
	else
	{
		fprintf( stderr, "Error RegCreateKeyEx" );
		return 1;
	}

    if ( system("echo hai") == -1 )
	{
		fprintf( stderr, "Error system echo hai" );
		return 1;
	}

    if ( WinExec("echo hi there", SW_SHOW) <= 31 )
	{
		fprintf( stderr, "Error WinExec" );
		return 1;
	}

    if ( CreateMutex(NULL, FALSE, _T("MutexNam3")) == NULL )
	{
		fprintf( stderr, "Error CreateMutex" );
		return 1;
	}
	if ( OpenMutex(MUTEX_ALL_ACCESS, FALSE, _T("OpenMutexName")) == NULL )
	{
		fprintf( stderr, "Error OpenMutex" );
		return 1;
	}

    // just some random dll
    if ( LoadLibrary( _T("urlmon.dll")) == NULL )
	{
		fprintf( stderr, "Error Loadlibrary urlmon" );
		return 1;
	}

    FARPROC sleep = GetProcAddress(GetModuleHandle(_T("kernel32")), "Sleep");
	if (sleep == NULL)
	{
		fprintf( stderr, "Error getprocaddress Sleep" );
		return 1;
	}

    sleep(1000);

    printf("debugger: %d\n", IsDebuggerPresent());

    CloseHandle(CreateThread(NULL, 0, &dummy, NULL, 0, NULL));

    HANDLE thread_handle = CreateRemoteThread(GetCurrentProcess(), NULL, 0,
        &dummy, NULL, 0, NULL);
	if (thread_handle == NULL)
	{
		fprintf( stderr, "Error CreateRemoteThread" );
		return 1;
	}
    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);

	return 0;
}
