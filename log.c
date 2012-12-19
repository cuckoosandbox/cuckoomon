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
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include <dirent.h>
#include "ntapi.h"
#include "misc.h"
#include "utf8.h"

// the size of the logging buffer
#define BUFFERSIZE 1024 * 1024

static CRITICAL_SECTION g_mutex;
static DWORD g_pid, g_ppid;
static wchar_t g_module_name_buf[MAX_PATH];
static const wchar_t *g_module_name;
static FILE *g_fp;

static char g_buffer[BUFFERSIZE];
static int g_idx;

//
// Log API
//

void log_flush()
{
    if(g_idx != 0) {
        unsigned int written = fwrite(g_buffer, 1, g_idx, g_fp);
        fflush(g_fp);

        // if this call didn't write the entire buffer, then we have to move
        // around some stuff in the buffer
        if(written < g_idx) {
            memcpy(g_buffer, g_buffer + written, g_idx - written);
        }

        // subtract the amount of written bytes from the index
        g_idx -= written;
    }
}

static void log_bytes(const void *bytes, int len)
{
    const unsigned char *b = (const unsigned char *) bytes;
    while (len--) {
        if(BUFFERSIZE - g_idx < 4) {
            log_flush();
        }
        if(*b >= ' ' && *b < 0x7f) {
            g_buffer[g_idx++] = *b;
        }
        else if(*b == '\r' || *b == '\n' || *b == '\t') {
            g_buffer[g_idx++] = '\\';
            g_buffer[g_idx++] = '\\';
            switch (*b) {
            case '\r': g_buffer[g_idx++] = 'r'; break;
            case '\n': g_buffer[g_idx++] = 'n'; break;
            case '\t': g_buffer[g_idx++] = 't'; break;
            }
        }
        else {
            g_buffer[g_idx++] = '\\';
            g_buffer[g_idx++] = '\\';
            g_buffer[g_idx++] = 'x';
            g_buffer[g_idx++] = "0123456789abcdef"[*b >> 4];
            g_buffer[g_idx++] = "0123456789abcdef"[*b & 15];
        }
        b++;
    }
}

static void log_string(const char *str, int len, int quotes)
{
    if(len == -1) len = strlen(str);

    if(quotes) log_bytes("\"", 1);
    while (len--) {
        if(*str == '"') {
            log_bytes("\"", 1);
        }
        log_bytes(str++, 1);
    }
    if(quotes) log_bytes("\"", 1);
}

// utf8 encodes an utf16 wchar_t
static void log_wchar(unsigned short c)
{
    unsigned char buf[3]; int len;
    len = utf8_encode(c, buf);
    log_bytes(buf, len);
}

static void log_wstring(const wchar_t *str, int len, int quotes)
{
    if(len == -1) len = lstrlenW(str);

    if(quotes) log_bytes("\"", 1);
    while (len--) {
        if(*str == '"') {
            log_bytes("\"", 1);
        }
        log_wchar(*(unsigned short *) str++);
    }
    if(quotes) log_bytes("\"", 1);
}

static void log_itoa(unsigned long value, int base, int width, int nullpad)
{
    char buf[32] = {0}; int i;

    for (i = 30; value != 0 && i != 0; i--, value /= base, width--) {
        buf[i] = "0123456789abcdef"[value % base];
    }

    // if value is zero
    if(i == 30 && width == 0) {
        buf[i--] = '0';
    }

    while (width-- > 0) {
        buf[i--] = nullpad ? '0' : ' ';
    }

    log_string(&buf[i + 1], -1, 0);
}

static void log_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    while (*fmt != 0) {
        if(*fmt != '%') {
            log_bytes(fmt++, 1);
            continue;
        }

        int done = 0, nullpad = 0, width = 0;

        while (done == 0) {
            switch (*++fmt) {
            case '%':
                log_bytes(fmt, 1);
                done = 1;
                break;

            case '0':
                nullpad = 1;
                break;

            case '1': case '2': case '3': case '4': case '5':
            case '6': case '7': case '8': case '9':
                width = width * 10 + *fmt - '0';
                break;

            case 'l':
                break;

            case 'd':
                log_itoa(va_arg(args, long), 10, width, nullpad);
                done = 1;
                break;

            case 'p':
                log_bytes("0x", 2);
                log_itoa(va_arg(args, long), 16, 2 * sizeof(long), 1);
                done = 1;
                break;

            case 's':
                log_string(va_arg(args, const char *), -1, 0);
                done = 1;
                break;

            case 'S':
                log_wstring(va_arg(args, const wchar_t *), -1, 0);
                done = 1;
                break;

            default:
                // dafuq?
                fprintf(stderr, "invalid format specifier.. %c\n", *fmt);
                break;
            }
        }
        fmt++;
    }

    va_end(args);
}

void loq(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int count = 1; char key = 0;

    EnterCriticalSection(&g_mutex);

    SYSTEMTIME st;
    GetSystemTime(&st);

    g_idx = 0;

    log_printf("\"%d-%02d-%02d %02d:%02d:%02d,%03d\",", st.wYear, st.wMonth,
        st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    const char *module_name = va_arg(args, const char *);
    const char *function_name = va_arg(args, const char *);
    int is_success = va_arg(args, int);
    long return_value = va_arg(args, long);

    // first parameter in args indicates the hooking type
    log_printf("\"%d\",\"%S\",\"%d\",\"%d\",\"%s\",\"%s\",\"%s\",\"%p\"",
        g_pid, g_module_name, GetCurrentThreadId(), g_ppid, module_name,
        function_name, is_success != 0 ? "SUCCESS" : "FAILURE", return_value);

    while (--count || *fmt != 0) {
        log_bytes(",", 1);

        // we have to find the next format specifier
        if(count == 0) {
            // end of format
            if(*fmt == 0) break;

            // set the count, possibly with a repeated format specifier
            count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;

            // the next format specifier
            key = *fmt++;
        }

        // log the key
        const char *key_str = va_arg(args, const char *);
        log_printf("\"%s->", key_str);

        // log the value
        if(key == 's') {
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "";
            log_string(s, -1, 0);
        }
        else if(key == 'S') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            log_string(s, len, 0);
        }
        else if(key == 'u') {
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"";
            log_wstring(s, -1, 0);
        }
        else if(key == 'U') {
            int len = va_arg(args, int);
            const wchar_t *s = va_arg(args, const wchar_t *);
            (void)len;
            log_wstring(s, len, 0);
        }
        else if(key == 'b') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            (void)len;
            log_printf("%p", s);
        }
        else if(key == 'B') {
            int *len = va_arg(args, int *);
            const char *s = va_arg(args, const char *);
            (void)len;
            log_printf("%p", s);
        }
        else if(key == 'i') {
            int value = va_arg(args, int);
            log_printf("%d", value);
        }
        else if(key == 'l' || key == 'p') {
            long value = va_arg(args, long);
            log_printf(key == 'l' ? "%ld" : "%p", value);
        }
        else if(key == 'L' || key == 'P') {
            void **ptr = va_arg(args, void **);
            log_printf(key == 'L' ? "%ld" : "%p",
                ptr != NULL ? *ptr : NULL);
        }
        else if(key == 'o') {
            UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
            if(str == NULL) {
                log_string("", 0, 0);
            }
            else {
                log_wstring(str->Buffer, str->Length >> 1, 0);
            }
        }
        else if(key == 'O') {
            OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
            if(obj == NULL || obj->ObjectName == NULL) {
                log_string("", 0, 0);
            }
            else {
                log_wstring(obj->ObjectName->Buffer,
                    obj->ObjectName->Length >> 1, 0);
            }
        }
        else if(key == 'a') {
            int argc = va_arg(args, int);
            const char **argv = va_arg(args, const char **);
            log_bytes("[", 1);
            while (argc--) {
                log_string(*argv++, -1, 0);
                if(argc != 0) {
                    log_bytes(", ", 2);
                }
            }
            log_bytes("]", 1);
        }
        else if(key == 'A') {
            int argc = va_arg(args, int);
            const wchar_t **argv = va_arg(args, const wchar_t **);
            log_bytes("[", 1);
            while (argc--) {
                log_wstring(*argv++, -1, 0);
                if(argc != 0) {
                    log_bytes(", ", 2);
                }
            }
            log_bytes("]", 1);
        }
        else if(key == 'r' || key == 'R') {
            unsigned long type = va_arg(args, unsigned long);
            unsigned long size = va_arg(args, unsigned long);
            unsigned char *data = va_arg(args, unsigned char *);

            if(data == NULL || type == REG_NONE) {
                log_string("<None>", -1, 0);
            }
            else if(type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_printf("%d", value);
            }
            else if(type == REG_DWORD_BIG_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_printf("%d", htonl(value));
            }
            else if(type == REG_EXPAND_SZ || type == REG_SZ) {
                // ascii strings
                if(key == 'r') {
                    log_string((const char *) data, size, 0);
                }
                // unicode strings
                else {
                    log_wstring((const wchar_t *) data, size >> 1, 0);
                }
            }
        }
        log_bytes("\"", 1);
    }

    va_end(args);

    g_buffer[g_idx++] = '\n';

    // make sure this entry is written to the log file
    log_flush();

    LeaveCriticalSection(&g_mutex);
}

void log_init(int debug)
{
    InitializeCriticalSection(&g_mutex);
    GetModuleFileNameW(NULL, g_module_name_buf, ARRAYSIZE(g_module_name_buf));

    // extract only the filename of the process, not the entire path
    for (const wchar_t *p = g_module_name = g_module_name_buf; *p != 0; p++) {
        if(*p == '\\' || *p == '/') {
            g_module_name = p + 1;
        }
    }

    g_pid = GetCurrentProcessId();
    g_ppid = parent_process_id();

    mkdir("C:\\cuckoo");
    mkdir("C:\\cuckoo\\logs");

    if(debug != 0) {
        g_fp = stderr;
    }
    else {
        char fname[256];
        sprintf(fname, "C:\\cuckoo\\logs\\%d.csv", GetCurrentProcessId());
        g_fp = fopen(fname, "w");
    }
}

void log_free()
{
    DeleteCriticalSection(&g_mutex);
    if(g_fp != stderr) {
        log_flush();
        fclose(g_fp);
    }
}
