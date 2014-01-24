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

ULONG_PTR parent_process_id(); // By Napalm @ NetCore2K (rohitab.com)
DWORD pid_from_process_handle(HANDLE process_handle);
DWORD pid_from_thread_handle(HANDLE thread_handle);
DWORD random();
DWORD randint(DWORD min, DWORD max);
BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj);
void hide_module_from_peb(HMODULE module_handle);

uint32_t path_from_handle(HANDLE handle,
    wchar_t *path, uint32_t path_buffer_len);

uint32_t path_from_object_attributes(const OBJECT_ATTRIBUTES *obj,
    wchar_t *path, uint32_t buffer_length);

int ensure_absolute_path(wchar_t *out, const wchar_t *in, int length);

// imported but for some doesn't show up when #including string.h etc
int wcsnicmp(const wchar_t *a, const wchar_t *b, int len);
int wcsicmp(const wchar_t *a, const wchar_t *b);

// Define MAX_PATH plus tolerance for windows "tolerance"
#define MAX_PATH_PLUS_TOLERANCE MAX_PATH + 64
