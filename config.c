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
#include "ntapi.h"
#include "config.h"

void read_config()
{
    // TODO unicode support
    char buf[512], config_fname[MAX_PATH];
    sprintf(config_fname, "%s\\%d.ini",
        getenv("TEMP"), GetCurrentProcessId());

    FILE *fp = fopen(config_fname, "r");
    if(fp != NULL) {
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            // cut off the newline
            char *p = strchr(buf, '\r');
            if(p != NULL) *p = 0;
            p = strchr(buf, '\n');
            if(p != NULL) *p = 0;

            // split key=value
            p = strchr(buf, '=');
            if(p != NULL) {
                *p = 0;

                const char *key = buf, *value = p + 1;

                if(!strcmp(key, "pipe")) {
                    strncpy(g_config.pipe_name, value,
                        ARRAYSIZE(g_config.pipe_name));
                }
                else if(!strcmp(key, "results")) {
                    strncpy(g_config.results, value,
                        ARRAYSIZE(g_config.results));
                }
                else if(!strcmp(key, "analyzer")) {
                    strncpy(g_config.analyzer, value,
                        ARRAYSIZE(g_config.analyzer));
                }
                else if(!strcmp(key, "first-process")) {
                    g_config.first_process = value[0] == '1';
                }
                else if(!strcmp(key, "startup-time")) {
                    g_config.startup_time = atoi(value);
                }
                else if(!strcmp(key, "retaddr-check")) {
                    g_config.retaddr_check = value[0] == '1';
                }
                else if(!strcmp(key, "host-ip")) {
                    g_config.host_ip = inet_addr(value);
                }
                else if(!strcmp(key, "host-port")) {
                    g_config.host_port = atoi(value);
                }
            }
        }
        fclose(fp);
        DeleteFile(config_fname);
    }
}
