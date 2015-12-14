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

typedef struct _hook_info_t {
    unsigned int depth_count;

    unsigned int hook_count;
    unsigned int retaddr_esp;

    unsigned int last_error;
    unsigned int ret_last_error;

    // in case of an exception, this is the state of all registers upon
    // execution of our hook
    unsigned int eax;
    unsigned int ecx;
    unsigned int edx;
    unsigned int ebx;
    unsigned int esp;
    unsigned int ebp;
    unsigned int esi;
    unsigned int edi;
} hook_info_t;

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
    // (see comments @ hook_create_pre_trampoline)
    int allow_hook_recursion;

    // this hook has been performed
    int is_hooked;

    unsigned char tramp[128];
    unsigned char pre_tramp[150];
    unsigned char store_exc[128];
    unsigned char hook_data[32];
} hook_t;

int lde(void *addr);

int hook_api(hook_t *h, int type);

hook_info_t* hook_info();
void hook_enable();
void hook_disable();

int hook_is_inside();

unsigned int hook_get_last_error();
void hook_set_last_error(unsigned int errcode);

void hook_disable_retaddr_check();

#define HOOK_BACKTRACE_DEPTH 20

#define HOOK_ENABLE_FPU 0

enum {
    HOOK_JMP_DIRECT,
    HOOK_NOP_JMP_DIRECT,
    HOOK_HOTPATCH_JMP_DIRECT,
    HOOK_PUSH_RETN,
    HOOK_NOP_PUSH_RETN,
    HOOK_JMP_INDIRECT,
    HOOK_MOV_EAX_JMP_EAX,
    HOOK_MOV_EAX_PUSH_RETN,
    HOOK_MOV_EAX_INDIRECT_JMP_EAX,
    HOOK_MOV_EAX_INDIRECT_PUSH_RETN,
#if HOOK_ENABLE_FPU
    HOOK_PUSH_FPU_RETN,
#endif
    HOOK_SPECIAL_JMP,
    HOOK_TECHNIQUE_MAXTYPE,
};

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
