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
#include "misc.h"

#define UNHOOK_MAXCOUNT 2048
#define UNHOOK_BUFSIZE 256

static HANDLE g_unhook_thread_handle, g_watcher_thread_handle;

// Index for adding new hooks and iterating all existing hooks.
static uint32_t g_index = 0;

// Length of this region.
static uint32_t g_length[UNHOOK_MAXCOUNT];

// Address of the region.
static const uint8_t *g_addr[UNHOOK_MAXCOUNT];

// Function name of the region.
static char g_funcname[UNHOOK_MAXCOUNT][64];

// The original contents of this region, before we modified it.
static uint8_t g_orig[UNHOOK_MAXCOUNT][UNHOOK_BUFSIZE];

// The contents of this region after we modified it.
static uint8_t g_our[UNHOOK_BUFSIZE][UNHOOK_BUFSIZE];

// If the region has been modified, did we report this already?
static uint8_t g_hook_reported[UNHOOK_MAXCOUNT];

void unhook_detect_add_region(const char *funcname, const uint8_t *addr,
    const uint8_t *orig, const uint8_t *our, uint32_t length)
{
    if(g_index == UNHOOK_MAXCOUNT) {
        pipe("CRITICAL:Reached maximum number of unhook detection entries!");
        return;
    }

    g_length[g_index] = length;
    g_addr[g_index] = addr;

    if(funcname != NULL) {
        strcpy(g_funcname[g_index], funcname);
    }

    memcpy(g_orig[g_index], orig, MIN(length, UNHOOK_BUFSIZE));
    memcpy(g_our[g_index], our, MIN(length, UNHOOK_BUFSIZE));
    g_index++;
}

static DWORD WINAPI _unhook_detect_thread(LPVOID param)
{
    static int watcher_first = 1;

    hook_disable();

    while (1) {
        if(WaitForSingleObject(g_watcher_thread_handle,
                500) != WAIT_TIMEOUT) {
            if(watcher_first != 0) {
                if(is_shutting_down() == 0) {
                    log_anomaly("unhook", 1, NULL,
                        "Unhook watcher thread has been corrupted!");
                }
                watcher_first = 0;
            }
            Sleep(100);
        }

        for (uint32_t idx = 0; idx < g_index; idx++) {
            // Check whether this memory region still equals what we made it.
            if(!memcmp(g_addr[idx], g_our[idx], g_length[idx])) {
                continue;
            }

            // By default we assume the hook has been modified.
            const char *msg = "Function hook was modified!";

            // If the memory region matches the original contents, then it
            // has been restored to its original state.
            if(!memcmp(g_orig[idx], g_addr[idx], g_length[idx])) {
                msg = "Function was unhooked/restored!";
            }

            if(g_hook_reported[idx] == 0) {
                if(is_shutting_down() == 0) {
                    log_anomaly("unhook", 1, g_funcname[idx], msg);
                }
                g_hook_reported[idx] = 1;
            }
        }
    }

    return 0;
}

static DWORD WINAPI _unhook_watch_thread(LPVOID param)
{
    hook_disable();

    while (WaitForSingleObject(g_unhook_thread_handle, 1000) == WAIT_TIMEOUT);

    if(is_shutting_down() == 0) {
        log_anomaly("unhook", 1, NULL,
            "Unhook detection thread has been corrupted!");
    }
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
