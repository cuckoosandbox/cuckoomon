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
#include "log.h"

const char *module_name = "logging";

int main()
{
    /*
    int is_success(int ret) { return 1; }
    int ret = 0;

    log_init(0, 0, 1);

    LOQ("2s", "a", "b", "c", "d");
    LOQ("S", "a", 4, "hello");
    LOQ("U", "b", 4, L"ab\u1337c");
    LOQ("s", "c", NULL);
    LOQ("lUl", "a", 32, "b", 6, L"HelloWorld", "c", 32);

    // utf8 encoding examples from wikipedia, should result in the following:
    // "\x24\xc2\xa2\xe2\x82\xac"
    LOQ("u", "a", L"\u0024\u00a2\u20ac");

    int argc = 4;
    char *argv[] = {"a", "b", "c", "d"};
    LOQ("a", "a", argc, argv);

    // registry stuff
    LOQ("r", "a", REG_SZ, 0, "lolz");
    LOQ("r", "a", REG_DWORD, 4, "\x10\x00\x00\x00");
    LOQ("R", "a", REG_SZ, 1337, L"omgz0r");
    LOQ("R", "a", REG_BINARY, 8, "Hello World");
*/
	return 0;
}
