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
#include <wininet.h>

int print_url_contents(const char *url)
{
    HINTERNET internet_handle, request_handle;
    char buffer[1024]; 
	unsigned long bytes_read;

    internet_handle = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL,
        NULL, 0);
    if(internet_handle == NULL)  
	{
		fprintf( stderr, "Error InternetOpen" );
		return 1;
	}

    request_handle = InternetOpenUrlA(internet_handle, url, NULL, 0, 0, 0);
    if(request_handle == NULL) {
		fprintf( stderr, "Error InternetOpenUrlA" );
        InternetCloseHandle(internet_handle);
        return 1;
    }

    while (InternetReadFile(request_handle, buffer, sizeof(buffer),
            &bytes_read) != FALSE && bytes_read != 0) {
        fwrite(buffer, bytes_read, 1, stderr);
    }

    InternetCloseHandle(internet_handle);
    InternetCloseHandle(request_handle);

    return 0;
}

int main( void )
{
    return print_url_contents("http://jbremer.org/");
}
