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
    if(argc == 4) {
        Sleep(5000);
        return 0;
    }

    Sleep(10000);

    char buf[256];
    sprintf(buf, "%s a b c", argv[0]);
    if ( system(buf) == -1 )
	{
		fprintf( stderr, "Error system buf %s\n", buf );

		return 1;
	}

	return 0;
}
