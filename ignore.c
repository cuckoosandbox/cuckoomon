/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2012 Cuckoo Sandbox Developers

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
#include "ignore.h"

static unsigned long g_pids[MAX_PROTECTED_PIDS];
static unsigned long g_pid_count;

void add_protected_pid(unsigned long pid)
{
    g_pids[g_pid_count++] = pid;
}

int is_protected_pid(unsigned long pid)
{
    for (unsigned long i = 0; i < g_pid_count; i++) {
        if(pid == g_pids[i]) {
            return 1;
        }
    }
    return 0;
}
