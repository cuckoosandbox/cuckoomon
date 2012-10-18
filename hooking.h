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

typedef struct _hook_t {
    const wchar_t *library;
    const char *funcname;

    // instead of a library/funcname combination, an address can be given
    // as well (this address has more priority than library/funcname)
    void *addr;

    // pointer to the new function
    void *new_func;

    // "function" which jumps over the trampoline and executes the original
    // function call
    void **old_func;

    // allow hook recursion on this hook?
    // (see comments @ hook_create_pre_gate)
    int allow_hook_recursion;

    // this hook has been performed
    int is_hooked;

    unsigned char gate[128];
    unsigned char pre_gate[128];
    unsigned char hook_data[32];
} hook_t;

int lde(void *addr);

int hook_create_callgate(unsigned char *addr, int len, unsigned char *gate);

int hook_api(hook_t *h, int type);

void hook_enable();
void hook_disable();

unsigned int hook_get_last_error();
void hook_set_last_error(unsigned int errcode);

#define HOOK_JMP_DIRECT 0
#define HOOK_NOP_JMP_DIRECT 1
#define HOOK_HOTPATCH_JMP_DIRECT 2
#define HOOK_PUSH_RETN 3
#define HOOK_JMP_INDIRECT 4
#define HOOK_MOV_EAX_JMP_EAX 5
#define HOOK_MOV_EAX_PUSH_RETN 6
#define HOOK_MOV_EAX_INDIRECT_JMP_EAX 7
#define HOOK_MOV_EAX_INDIRECT_PUSH_RETN 8
#define HOOK_PUSH_FPU_RETN 9
#define HOOK_MAXTYPE 10 // value to be used in modulo statements

#define HOOKDEF(return_value, calling_convention, apiname, ...) \
    return_value (calling_convention *Old_##apiname)(__VA_ARGS__); \
    return_value calling_convention New_##apiname(__VA_ARGS__)

#define HOOKDEF2(return_value, calling_convention, apiname, ...) \
    return_value (calling_convention *Old2_##apiname)(__VA_ARGS__); \
    return_value calling_convention New2_##apiname(__VA_ARGS__)

// each thread has a special 260-wchar counting unicode_string buffer in its
// thread information block, this is likely to be overwritten in certain
// functions, therefore we have this macro which copies it to the stack.
// (so we can use the unicode_string after executing the original function)
#define COPY_UNICODE_STRING(local_name, param_name) \
    UNICODE_STRING local_name = {0}; wchar_t local_name##_buf[260]; \
    local_name.Buffer = local_name##_buf; \
    if(param_name != NULL && param_name->MaximumLength < 520) { \
        local_name.Length = param_name->Length; \
        local_name.MaximumLength = param_name->MaximumLength; \
        memcpy(local_name.Buffer, param_name->Buffer, \
            local_name.MaximumLength); \
    }
