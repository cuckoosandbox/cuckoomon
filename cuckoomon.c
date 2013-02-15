/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2013 Cuckoo Sandbox Developers

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
#include "ntapi.h"
#include "hooking.h"
#include "hooks.h"
#include "log.h"
#include "pipe.h"
#include "ignore.h"
#include "hook_file.h"
#include "hook_sleep.h"
#include "config.h"

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if(dwReason == DLL_PROCESS_ATTACH) {
        // make sure advapi32 is loaded
        LoadLibrary("advapi32");

        // there's a small list of processes which we don't want to inject
        if(is_ignored_process()) {
            return TRUE;
        }

        // obtain all protected pids
        int pids[MAX_PROTECTED_PIDS], length = sizeof(pids);
        pipe2(pids, &length, "GETPIDS");
        for (int i = 0; i < length / sizeof(pids[0]); i++) {
            add_protected_pid(pids[i]);
        }

        // initialize file stuff
        file_init();

        // read the config settings
        read_config();
        g_pipe_name = g_config.pipe_name;

        // initialize the log file
        log_init(g_config.results, 0);

        // initialize the Sleep() skipping stuff
        init_sleep_skip(g_config.first_process);

        // disable the retaddr check if the user wants so
        if(g_config.retaddr_check == 0) {
            hook_disable_retaddr_check();
        }

        // initialize return address stuff
        init_ignored_retaddr(g_config.is_injected);

        // initialize all hooks
        set_hooks();

        // notify analyzer.py that we've loaded
        char name[64];
        sprintf(name, "CuckooEvent%d", GetCurrentProcessId());
        HANDLE event_handle = OpenEvent(EVENT_ALL_ACCESS, FALSE, name);
        if(event_handle != NULL) {
            SetEvent(event_handle);
            CloseHandle(event_handle);
        }
    }
    else if(dwReason == DLL_PROCESS_DETACH) {
        log_free();
    }

    return TRUE;
}
