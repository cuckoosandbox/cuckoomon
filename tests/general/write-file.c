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
#include <stdlib.h>

int main( void )
{
    const char *fnames[] = {
        "C:\\a.txt",
        "C:\\b.txt",
        "C:\\c.txt",
        "C:\\d.txt",
        "C:\\e.txt",
    };

    FILE *fp[5];
    for (int i = 0; i < 5; i++) {
        fp[i] = fopen(fnames[i], "w");
		if ( fp[i] == NULL )
		{
			fprintf( stderr, "Error fopen" );
			return 1;
		}

    }

    for (int i = 0; i < 20; i++) {
        if ( fprintf(fp[rand() % 5], "Hello %d\n", i) < 0 )
		{
			fprintf( stderr, "Error fprintf" );
			return 1;
		}
    }

    for (int i = 0; i < 20; i++) {
        int idx = rand() % 5;
        if(fp[idx] != NULL) {
            fclose(fp[idx]);
            fp[idx] = NULL;
        }
    }

	return 0;
}
