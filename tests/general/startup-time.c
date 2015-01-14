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
#include <stdint.h>
#include <windows.h>

// Idea originally taken from the following article
// http://spth.virii.lu/v4/articles/m0sa/evade.html

int main(void)
{
    if(GetTickCount() < 10 * 60 * 1000) {
        fprintf( stderr, "Running under a VM!\n");
		return 1;
    }
    else {
        printf("This computer is ok! Uptime: %d\n", GetTickCount());
    }

	return 0;
}
