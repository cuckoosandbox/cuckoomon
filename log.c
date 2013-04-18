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
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include <dirent.h>
#include <winsock.h>
#include "ntapi.h"
#include "misc.h"
#include "utf8.h"
#include "log.h"

// the size of the logging buffer
#define BUFFERSIZE 1024 * 1024
#define BUFFER_LOG_MAX 256

static CRITICAL_SECTION g_mutex;
static int g_sock;
static unsigned int g_starttick;

static char g_buffer[BUFFERSIZE];
static int g_idx;

//
// Log API
//

void log_flush()
{
    if(g_idx != 0) {
        int written;
        if(g_sock == INVALID_SOCKET) {
            written = fwrite(g_buffer, 1, g_idx, stderr);
        }
        else {
            written = send(g_sock, g_buffer, g_idx, 0);
        }

        // TODO add more error checking

        // if this call didn't write the entire buffer, then we have to move
        // around some stuff in the buffer
        if(written < g_idx) {
            memcpy(g_buffer, g_buffer + written, g_idx - written);
        }

        // subtract the amount of written bytes from the index
        g_idx -= written;
    }
}

static void log_int8(char value)
{
    if(g_idx >= BUFFERSIZE) {
        log_flush();
    }

    g_buffer[g_idx++] = value;
}

static void log_int16(short value)
{
    if(g_idx + 2 >= BUFFERSIZE) {
        log_flush();
    }

    *(short *) &g_buffer[g_idx] = value;
    g_idx += 2;
}

static void log_int32(int value)
{
    if(g_idx + 4 >= BUFFERSIZE) {
        log_flush();
    }

    *(int *) &g_buffer[g_idx] = value;
    g_idx += 4;
}

static void log_string(const char *str, int length)
{
    int encoded_length = 0;
    if(str == NULL) length = 0;
    else {
        if(length == -1) length = strlen(str);
        encoded_length = utf8_strlen_ascii(str, length);
    }

    // write the utf8 length
    log_int32(encoded_length);

    // and the maximum length (which is in fact the length in characters)
    log_int32(length);

    while (length > 0) {
        while (g_idx < BUFFERSIZE - 3 && length-- != 0) {
            g_idx += utf8_encode(*str++, (unsigned char *) &g_buffer[g_idx]);
        }

        if(g_idx > BUFFERSIZE - 4) {
            log_flush();
        }
    }
}

static void log_wstring(const wchar_t *str, int length)
{
    int encoded_length = 0;
    if(str == NULL) length = 0;
    else {
        if(length == -1) length = lstrlenW(str);
        encoded_length = utf8_strlen_unicode(str, length);
    }

    // write the utf8 length
    log_int32(encoded_length);

    // and the maximum length (which is in fact the length in characters)
    log_int32(length);

    while (length > 0) {
        while (g_idx < BUFFERSIZE - 3 && length-- != 0) {
            g_idx += utf8_encode(*str++, (unsigned char *) &g_buffer[g_idx]);
        }

        if(g_idx > BUFFERSIZE - 4) {
            log_flush();
        }
    }
}

static void log_argv(int argc, const char ** argv) {
    log_int32(argc);

    for (int i=0; i<argc; i++) {
        log_string(argv[i], -1);
    }
}

static void log_wargv(int argc, const wchar_t ** argv) {
    log_int32(argc);

    for (int i=0; i<argc; i++) {
        log_wstring(argv[i], -1);
    }
}

static void log_buffer(const char *buf, size_t length) {
    size_t trunclength = min(length, BUFFER_LOG_MAX);

    if (buf == NULL) {
        trunclength = 0;
    }

    log_int32(trunclength);
    log_int32(length);

    for (int i=0; i<trunclength; i++) {
        g_buffer[g_idx] = buf[i];
        g_idx++;

        if (g_idx >= BUFFERSIZE -1) {
            log_flush();
        }
    }
}

void loq(int index, int is_success, int return_value, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int count = 1; char key = 0;

    EnterCriticalSection(&g_mutex);

    log_int8(index);
    log_int8(is_success);
    log_int32(return_value);
    log_int32(GetCurrentThreadId());
    log_int32(GetTickCount() - g_starttick);

    while (--count != 0 || *fmt != 0) {

        // we have to find the next format specifier
        if(count == 0) {
            // end of format
            if(*fmt == 0) break;

            // set the count, possibly with a repeated format specifier
            count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;

            // the next format specifier
            key = *fmt++;
        }

        // pop the key and omit it
        (void) va_arg(args, const char *);

        // log the value
        if(key == 's') {
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "";
            log_string(s, -1);
        }
        else if(key == 'S') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            log_string(s, len);
        }
        else if(key == 'u') {
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"";

            log_wstring(s, -1);
        }
        else if(key == 'U') {
            int len = va_arg(args, int);
            const wchar_t *s = va_arg(args, const wchar_t *);
            log_wstring(s, len);
        }
        else if(key == 'b') {
            size_t len = va_arg(args, size_t);
            const char *s = va_arg(args, const char *);
            log_buffer(s, len);
        }
        else if(key == 'B') {
            size_t *len = va_arg(args, size_t *);
            const char *s = va_arg(args, const char *);
            log_buffer(s, *len);
        }
        else if(key == 'i') {
            int value = va_arg(args, int);
            log_int32(value);
        }
        else if(key == 'l' || key == 'p') {
            long value = va_arg(args, long);
            log_int32(value);
        }
        else if(key == 'L' || key == 'P') {
            long *ptr = va_arg(args, long *);
            log_int32(ptr != NULL ? *ptr : 0);
        }
        else if(key == 'o') {
            UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
            if(str == NULL) {
                log_string("", 0);
            }
            else {
                log_wstring(str->Buffer, str->Length / sizeof(wchar_t));
            }
        }
        else if(key == 'O') {
            OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
            if(obj == NULL || obj->ObjectName == NULL) {
                log_string("", 0);
            }
            else {
                log_wstring(obj->ObjectName->Buffer,
                    obj->ObjectName->Length / sizeof(wchar_t));
            }
        }
        else if(key == 'a') {
            int argc = va_arg(args, int);
            const char **argv = va_arg(args, const char **);
            log_argv(argc, argv);
        }
        else if(key == 'A') {
            int argc = va_arg(args, int);
            const wchar_t **argv = va_arg(args, const wchar_t **);
            log_wargv(argc, argv);
        }
        else if(key == 'r' || key == 'R') {
            unsigned long type = va_arg(args, unsigned long);
            unsigned long size = va_arg(args, unsigned long);
            unsigned char *data = va_arg(args, unsigned char *);

            log_int32(type);

            if(type == REG_NONE) {
                log_string("", 0);
            }
            else if(type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(value);
            }
            else if(type == REG_DWORD_BIG_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(htonl(value));
            }
            else if(type == REG_EXPAND_SZ || type == REG_SZ) {
                // ascii strings
                if(key == 'r') {
                    log_string((const char *) data, size);
                }
                // unicode strings
                else {
                    log_wstring((const wchar_t *) data,
                        size / sizeof(wchar_t));
                }
            }
        }
    }

    va_end(args);

    log_flush();
    LeaveCriticalSection(&g_mutex);
}

void announce_netlog()
{
    char protoname[] = "NETLOG\n";
    for (int i=0; i<strlen(protoname); i++) {
        g_buffer[g_idx] = protoname[i];
        g_idx++;
    }
}

void log_new_process()
{
    wchar_t module_path[MAX_PATH];
    GetModuleFileNameW(NULL, module_path, ARRAYSIZE(module_path));

    g_starttick = GetTickCount();

    FILETIME st;
    GetSystemTimeAsFileTime(&st);

    loq(0, 1, 0, "llllu", "TimeLow", st.dwLowDateTime,
        "TimeHigh", st.dwHighDateTime,
        "ProcessIdentifier", GetCurrentProcessId(),
        "ParentProcessIdentifier", parent_process_id(),
        "ModulePath", module_path);
}

void log_new_thread()
{
    loq(1, 1, 0, "l", "ProcessIdentifier", GetCurrentProcessId());
}

void log_init(unsigned int ip, unsigned short port, int debug)
{
    InitializeCriticalSection(&g_mutex);

    if(debug != 0) {
        g_sock = INVALID_SOCKET;
    }
    else {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        struct sockaddr_in addr = {
            .sin_family         = AF_INET,
            .sin_addr.s_addr    = ip,
            .sin_port           = htons(port),
        };

        connect(g_sock, (struct sockaddr *) &addr, sizeof(addr));
    }

    announce_netlog();
    log_new_process();
    log_new_thread();
    // flushing here so host can create files / keep timestamps
    log_flush();
}

void log_free()
{
    DeleteCriticalSection(&g_mutex);
    log_flush();
    if(g_sock != INVALID_SOCKET) {
        closesocket(g_sock);
    }
}

int log_resolve_index(const char *funcname, int index)
{
    for (int i = 0; logtbl[i] != NULL; i++) {
        if(!strcmp(funcname, logtbl[i])) {
            if(index != 0) {
                index--;
            }
            else {
                return i;
            }
        }
    }
    return -1;
}
