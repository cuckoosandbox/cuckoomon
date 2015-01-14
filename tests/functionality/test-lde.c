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
#include "../hooking.h"

int main(void)
{
	/*
	55                       | push ebp                                
	89 E5                    | mov ebp,esp                             
	83 EC 18                 | sub esp,18                             
	*/
    unsigned char b[][8] = {
        {0x55}, 
        {0x89, 0xe5},
        {0x83, 0xec, 0x18},
    };

    for (int i = 0; i < sizeof(b)/sizeof(b[0]); i++) {
        printf("%d\n", lde(b[i]));
    }

	return 0;
}
