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

#define _WIN32_WINNT 0x0501
#include <stdio.h>
#include <windows.h>
#include <windns.h>
#include <ws2tcpip.h>
#include <tchar.h>

int main(void)
{
	DNS_STATUS status;
	int returnf;
	struct hostent * returnfhost;

    if ( LoadLibrary(_T("../../cuckoomon.dll")) == NULL )
	{
		fprintf( stderr, "Error Loadlibrary cuckoomon" );
		return 1;
	}

	status = DnsQuery(_T("jbremer.org"), DNS_TYPE_A,
		DNS_QUERY_STANDARD, NULL, NULL, NULL);
    printf("DnsQuery -> %d\n", status );
	if (status)
	{
		fprintf( stderr, "Error" );
		return 1;
	}

	struct addrinfo *info = NULL;
	returnf = getaddrinfo(_T("jbremer.org"), NULL, NULL,&info);
    
    printf("getaddrinfo -> %d\n", returnf );
	if ( returnf != 0 )
	{
		fprintf( stderr, "Error" );
		return 1;
	}

	returnfhost = gethostbyname(_T("jbremer.org"));
    printf("gethostbyname -> %p\n", returnfhost);

	if ( returnfhost == NULL )
	{
		fprintf( stderr, "Error" );
		return 1;
	}

	return 0;
}
