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

int main(void)
{
    const char *modes[] = {"r", "r+", "w", "w+", "a", "a+"};
    const char *fname = "abc";
	FILE * file;

    for (int i = 0; i < sizeof(modes)/sizeof(char *); i++) 
	{
        if ( DeleteFileA(fname) == 0 )
		{
			fprintf( stderr, "Error DeleteFileA" );
			return 1;
		}
        FILE *fp = fopen(fname, modes[i]);
        if(fp != NULL) 
            fclose(fp);
		else
		{
			fprintf( stderr, "Error fopen %s mode %s\n", fname, modes[i] );
			return 1;
		}
    }

	file = fopen(fname, "w");
	if ( file == NULL )
	{
		fprintf( stderr, "Error fopen %s\n", fname );
		return 1;
	}
    fclose( file );
    for (int i = 0; i < sizeof(modes)/sizeof(char *); i++) 
	{
        FILE *fp = fopen(fname, modes[i]);
        if(fp != NULL) 
            fclose(fp);
		else
		{
			fprintf( stderr, "Error fopen %s mode %s\n", fname,  modes[i] );
			return 1;
		}
    }

	return 0;
}
