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
#include "ntapi.h"
#include "hooking.h"
#include "pipe.h"
#include "log.h"

#define UNHOOK_MAXCOUNT 2048
#define UNHOOK_BUFSIZE 256

static HANDLE g_unhook_thread_handle, g_watcher_thread_handle;

static uint32_t g_index = 0;
static uint32_t g_length[UNHOOK_MAXCOUNT];
static const uint8_t *g_addr[UNHOOK_MAXCOUNT];
static uint8_t g_orig[UNHOOK_MAXCOUNT][UNHOOK_BUFSIZE];

void unhook_detect_add_region(const uint8_t *addr,
    const uint8_t *orig, uint32_t length)
{
    if(g_index == UNHOOK_MAXCOUNT) {
        pipe("CRITICAL:Reached maximum number of unhook detection entries!");
        return;
    }

    g_length[g_index] = length;
    g_addr[g_index] = addr;
    memcpy(g_orig[g_index], orig, MIN(length, UNHOOK_BUFSIZE));
    g_index++;
}

static DWORD WINAPI _unhook_detect_thread(LPVOID param)
{
    static int watcher_first = 1, hook_first = 1;

    hook_disable();

    while (1) {
        if(WaitForSingleObject(g_watcher_thread_handle,
                500) != WAIT_TIMEOUT) {
            if(watcher_first != 0) {
                log_anomaly("unhook", 1,
                    "Unhook watcher thread has been corrupted!");
                watcher_first = 0;
            }
            Sleep(100);
        }

        for (uint32_t idx = 0; idx < g_index; idx++) {
            if(!memcmp(g_addr[idx], g_orig[idx], g_length[idx])) {
                continue;
            }

            if(hook_first != 0) {
                log_anomaly("unhook", 1, "Hook modification detected!");
                hook_first = 0;
            }
        }
    }

    return 0;
}

static DWORD WINAPI _unhook_watch_thread(LPVOID param)
{
    hook_disable();

    while (WaitForSingleObject(g_unhook_thread_handle, 1000) == WAIT_TIMEOUT);

    log_anomaly("unhook", 1, "Unhook detection threat has been corrupted!");
    return 0;
}

int unhook_init_detection()
{
    g_unhook_thread_handle =
        CreateThread(NULL, 0, &_unhook_detect_thread, NULL, 0, NULL);

    g_watcher_thread_handle =
        CreateThread(NULL, 0, &_unhook_watch_thread, NULL, 0, NULL);

    if(g_unhook_thread_handle != NULL && g_watcher_thread_handle != NULL) {
        return 0;
    }

    pipe("CRITICAL:Error initializing unhook detection threads!");
    return -1;
}
