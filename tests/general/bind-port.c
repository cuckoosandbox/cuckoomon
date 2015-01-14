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
#include <winsock.h>

int main(void)
{
    WSADATA wsa;
    if ( WSAStartup(MAKEWORD(2, 2), &wsa) != 0 )
	{
		fprintf( stderr, "Error WSAStartup" );
		return 1;
	}

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);

	if ( s == INVALID_SOCKET )
	{
		fprintf( stderr, "Error socket" );
		return 1;
	}

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0;
    addr.sin_port = htons(0x29a);

    if ( bind(s, (struct sockaddr *) &addr, sizeof(addr)) != 0 )
	{
		fprintf( stderr, "Error bind" );
		return 1;
	}

	return 0;
}
