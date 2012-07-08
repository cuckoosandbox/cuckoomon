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
#include "ntapi.h"
#include "misc.h"

static CRITICAL_SECTION g_mutex;
static DWORD g_pid, g_ppid;
static wchar_t g_module_name_buf[256];
static const wchar_t *g_module_name;
static FILE *g_fp;

//
// Log API
//

static void log_bytes(const void *bytes, int len)
{
    const unsigned char *b = (const unsigned char *) bytes;
    while (len--) {
        if(*b >= ' ' && *b < 0x7f) {
            fwrite(b, 1, 1, g_fp);
        }
        else if(*b == '\r' || *b == '\n' || *b == '\t') {
            char ch = 'r';
            if(*b == '\n') ch = 'n';
            if(*b == '\t') ch = 't';
            fprintf(g_fp, "\\%c", ch);
        }
        else {
            fprintf(g_fp, "\\x%02x", *b);
        }
        b++;
    }
}

static void log_string(const char *str, int len, int quotes)
{
    if(len == -1) len = strlen(str);

    if(quotes) log_bytes("\"", 1);
    while (len--) {
        if(*str == '"' || *str == '\\') {
            log_bytes("\\", 1);
        }
        log_bytes(str++, 1);
    }
    if(quotes) log_bytes("\"", 1);
}

// utf8 encodes an utf16 wchar_t
static void log_wchar(unsigned short c)
{
    if(c < 0x80) {
        unsigned char b[] = {c & 0x7f};
        log_bytes(b, 1);
    }
    else if(c < 0x800) {
        unsigned char b[] = {
            0xc0 + ((c >> 8) << 2) + (c >> 6),
            0x80 + (c & 0x3f),
        };
        log_bytes(b, 2);
    }
    else {
        unsigned char b[] = {
            0xe0 + (c >> 12),
            0x80 + (((c >> 8) & 0x1f) << 2) + ((c >> 6) & 0x3),
            0x80 + (c & 0x3f),
        };
        log_bytes(b, 3);
    }
}

static void log_wstring(const wchar_t *str, int len, int quotes)
{
    if(len == -1) len = lstrlenW(str);

    if(quotes) log_bytes("\"", 1);
    while (len--) {
        if(*str == '"' || *str == '\\') {
            log_bytes("\\", 1);
        }
        log_wchar(*str++);
    }
    if(quotes) log_bytes("\"", 1);
}

static void log_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(g_fp, fmt, args);
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

    log_printf("\"%d-%02d-%02d %02d:%02d:%02d,%03d\",", st.wYear, st.wMonth,
        st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    const char *module_name = va_arg(args, const char *);
    const char *function_name = va_arg(args, const char *);
    int is_success = va_arg(args, int);
    long return_value = va_arg(args, long);

    // first parameter in args indicates the hooking type
    log_printf("\"%d\",\"%S\",\"%d\",\"%s\",\"%s\",\"%s\",\"0x%p\"", g_pid,
        g_module_name, g_ppid, module_name, function_name,
        is_success != 0 ? "SUCCESS" : "FAILURE", return_value);

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
            log_printf("0x%p", s);
        }
        else if(key == 'B') {
            int *len = va_arg(args, int *);
            const char *s = va_arg(args, const char *);
            (void)len;
            log_printf("0x%p", s);
        }
        else if(key == 'i') {
            int value = va_arg(args, int);
            log_printf("%d", value);
        }
        else if(key == 'l' || key == 'p') {
            long value = va_arg(args, long);
            log_printf(key == 'l' ? "%ld" : "0x%p", value);
        }
        else if(key == 'L' || key == 'P') {
            void **ptr = va_arg(args, void **);
            log_printf(key == 'L' ? "%ld" : "0x%p",
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
        log_bytes("\"", 1);
    }

    fprintf(g_fp, "\n");
    va_end(args);

    LeaveCriticalSection(&g_mutex);
}

void log_init()
{
    InitializeCriticalSection(&g_mutex);
    GetModuleFileNameW(NULL, g_module_name_buf, sizeof(g_module_name_buf));
    // extract only the filename of the process, not the entire path
    for (const wchar_t *p = g_module_name = g_module_name_buf; *p != 0; p++) {
        if(*p == '\\' || *p == '/') {
            g_module_name = p + 1;
        }
    }
    g_pid = GetCurrentProcessId();
    g_ppid = GetParentProcessId();

    char fname[256];
    sprintf(fname, "C:\\cuckoo\\logs\\%d.csv", GetCurrentProcessId());
    g_fp = fname != NULL ? fopen(fname, "w") : stderr;
}

void log_free()
{
    DeleteCriticalSection(&g_mutex);
    if(g_fp != stderr) {
        fclose(g_fp);
    }
}
