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
#include <stddef.h>
#include <windows.h>
#include "hooking.h"
#include "distorm.h"
#include "mnemonics.h"
#include "ntapi.h"
#include "ignore.h"

// this number can be changed if required to do so
#define TLS_HOOK_INFO 0x44

// do not change this number
#define TLS_LAST_ERROR 0x34

// hook return address stack space
#define TLS_HOOK_INFO_RETADDR_SPACE 0x100

static void ensure_valid_hook_info();

// by default we enable the retaddr check
static int g_enable_retaddr_check = 1;

// length disassembler engine
int lde(void *addr)
{
    // the length of an instruction is 16 bytes max, but there can also be
    // 16 instructions of length one, so.. we support "decomposing" 16
    // instructions at once, max
    unsigned int used_instruction_count; _DInst instructions[16];
    _CodeInfo code_info = {0, 0, addr, 16, Decode32Bits};
    _DecodeResult ret = distorm_decompose(&code_info, instructions, 16,
        &used_instruction_count);

    return ret == DECRES_SUCCESS ? instructions[0].size : 0;
}

static int is_interesting_backtrace(unsigned int ebp)
{
    // only perform this function when the retaddr-check is enabled, otherwise
    // return true in all cases (if retaddr-check is disabled, then every
    // backtrace is interesting)
    if(g_enable_retaddr_check == 0) {
        return 1;
    }

    // http://en.wikipedia.org/wiki/Win32_Thread_Information_Block
    unsigned int top = __readfsdword(0x04);
    unsigned int bottom = __readfsdword(0x08);

    unsigned int count = HOOK_BACKTRACE_DEPTH;
    while (ebp >= bottom && ebp < top && count-- != 0) {

        // obtain the return address and the next value of ebp
        unsigned int addr = *(unsigned int *)(ebp + 4);
        ebp = *(unsigned int *) ebp;

        // if this return address is *not* to be ignored, then it's
        // interesting
        if(is_ignored_retaddr(addr) == 0) {
            return 1;
        }
    }
    return 0;
}

// create a trampoline at the given address, that is, we are going to replace
// the original instructions at this particular address. So, in order to
// call the original function from our hook, we have to execute the original
// instructions *before* jumping into addr+offset, where offset is the length
// which totals the size of the instructions which we place in the `tramp'.
// returns 0 on failure, or a positive integer defining the size of the tramp
// NOTE: tramp represents the memory address where the trampoline will be
// placed, copying it to another memory address will result into failure
static int hook_create_trampoline(unsigned char *addr, int len,
    unsigned char *tramp)
{
    const unsigned char *base = tramp;

    // after the original function has returned, we have to make a backup of
    // the Last Error Code, so what we do is the following (we use the same
    // method below in the pre-tramp.) We store the current return address in
    // info->ret_last_error, then we overwrite the return address with a
    // return address in our trampoline. When we reach the trampoline, we make
    // a backup of the Last Error Code and jmp to the real return address.

    unsigned char pre_backup[] = {
        // push eax
        0x50,

        // mov eax, fs:[TLS_HOOK_INFO]
        0x64, 0xa1, TLS_HOOK_INFO, 0x00, 0x00, 0x00,
        // test eax, eax
        0x85, 0xc0,
        // jnz $+0d
        0x75, 0x0d,
            // pushad
            0x60,
            // call ensure_valid_hook_info
            0xe8, 0x00, 0x00, 0x00, 0x00,
            // popad
            0x61,
            // mov eax, fs:[TLS_HOOK_INFO]
            0x64, 0xa1, TLS_HOOK_INFO, 0x00, 0x00, 0x00,

        // cmp dword [eax+hook_info_t.hook_count], 0
        0x83, 0x78, offsetof(hook_info_t, hook_count), 0x00,
        // jg $+12
        0x7f, 0x12,
            // inc dword [eax+hook_info_t.hook_count]
            0xff, 0x40, offsetof(hook_info_t, hook_count),
            // push dword [esp+4]
            0xff, 0x74, 0xe4, 0x04,
            // pop dword [eax+hook_info_t.ret_last_error]
            0x8f, 0x40, offsetof(hook_info_t, ret_last_error),
            // mov dword [esp+4], new_return_address
            0xc7, 0x44, 0xe4, 0x04, 0x00, 0x00, 0x00, 0x00,

        // pop eax
        0x58,
    };

    // the function returns here after executing, backup the Last Error Code
    unsigned char post_backup[] = {
        // push eax
        0x50,
        // mov eax, fs:[TLS_HOOK_INFO]
        0x64, 0xa1, TLS_HOOK_INFO, 0x00, 0x00, 0x00,
        // dec dword [eax+hook_info_t.hook_count]
        0xff, 0x48, offsetof(hook_info_t, hook_count),
        // cmp dword [eax+hook_info_t.depth_count], 1
        0x83, 0x78, offsetof(hook_info_t, depth_count), 0x01,
        // jg $+0a
        0x7f, 0x0a,
            // push dword fs:[TLS_LAST_ERROR]
            0x64, 0xff, 0x35, TLS_LAST_ERROR, 0x00, 0x00, 0x00,
            // pop dword [eax+hook_info_t.last_error]
            0x8f, 0x40, offsetof(hook_info_t, last_error),
        // mov eax, dword [eax+hook_info_t.ret_last_error]
        0x8b, 0x40, offsetof(hook_info_t, ret_last_error),
        // xchg eax, dword [esp]
        0x87, 0x04, 0xe4,
        // retn
        0xc3,
    };

    *(unsigned int *)(pre_backup + 13) =
        (unsigned char *) &ensure_valid_hook_info - tramp - 12 - 5;

    memcpy(tramp, pre_backup, sizeof(pre_backup));
    tramp += sizeof(pre_backup);

    unsigned char **pre_backup_addr = (unsigned char **)(tramp - 5);

    // our trampoline should contain at least enough bytes to fit the given
    // length
    while (len > 0) {

        // obtain the length of this instruction
        int length = lde(addr);

        // error?
        if(length == 0) {
            return 0;
        }

        // how many bytes left?
        len -= length;

        // check the type of instruction at this particular address, if it's
        // a jump or a call instruction, then we have to calculate some fancy
        // addresses, otherwise we can simply copy the instruction to our
        // trampoline

        // it's a (conditional) jump or call with 32bit relative offset
        if(*addr == 0xe9 || *addr == 0xe8 || (*addr == 0x0f &&
                addr[1] >= 0x80 && addr[1] < 0x90)) {

            // copy the jmp or call instruction (conditional jumps are two
            // bytes, the rest is one byte)
            *tramp++ += *addr++;
            if(addr[-1] != 0xe9 && addr[-1] != 0xe8) {
                *tramp++ += *addr++;
            }

            // when a jmp/call is performed, then the relative offset +
            // the instruction pointer + the size of the instruction is the
            // calculated address, so that's our target address as well.
            // (note that `addr' is already increased by one or two, so the
            // 4 represents the 32bit offset of this particular instruction)
            unsigned long jmp_addr = *(unsigned long *) addr + 4 +
                (unsigned long) addr;
            addr += 4;

            // trampoline is already filled with the opcode itself (the jump
            // instruction), now we will actually jump to the location by
            // calculating the relative offset which points to the real
            // address (this is the reverse operation of the one to calculate
            // the absolute address of a jump)
            *(unsigned long *) tramp = jmp_addr - (unsigned long) tramp - 4;
            tramp += 4;

            // because an unconditional jump denotes the end of a basic block
            // we will return failure if we have not yet processed enough room
            // to store our hook code
            if(tramp[-5] == 0xe9 && len > 0) return 0;
        }
        // (conditional) jump with 8bit relative offset
        else if(*addr == 0xeb || (*addr >= 0x70 && *addr < 0x80)) {

            // same rules apply as with the 32bit relative offsets, except
            // for the fact that both conditional and unconditional 8bit
            // relative jumps take only one byte for the opcode

            // 8bit relative offset, we have to sign-extend it (by casting it
            // as signed char) in order to calculate the correct address
            unsigned long jmp_addr = (unsigned long) addr + 2 +
                *(signed char *)(addr + 1);

            // the chance is *fairly* high that we will not be able to perform
            // a jump from the trampoline to the original function, so instead
            // we will use 32bit relative offset jumps
            if(*addr == 0xeb) {
                *tramp++ = 0xe9;
            }
            else {
                // hex representation of the two types of 32bit jumps
                // 8bit relative conditional jumps:     70..80
                // 32bit relative conditional jumps: 0f 80..90
                // so we will simply add 0x10 to the opcode of 8bit relative
                // offset jump to obtain the 32bit relative offset jump opcode
                *tramp++ = 0x0f;
                *tramp++ = *addr + 0x10;
            }

            // calculate the correct relative offset address
            *(unsigned long *) tramp = jmp_addr - (unsigned long) tramp - 4;
            tramp += 4;

            // again, end of basic block, check for length
            if(*addr == 0xeb && len > 0) {
                return 0;
            }

            // add the instruction length
            addr += 2;
        }
        // return instruction, indicates end of basic block as well, so we
        // have to check if we already have enough space for our hook..
        else if((*addr == 0xc3 || *addr == 0xc2) && len > 0) {
            return 0;
        }
        else {
            // copy the instruction directly to the trampoline
            while (length-- != 0) {
                *tramp++ = *addr++;
            }
        }
    }

    // append a jump from the trampoline to the original function
    *tramp++ = 0xe9;
    *(unsigned int *) tramp =
        (unsigned int) addr - (unsigned int) tramp - 4;
    tramp += 4;

    // return address is the next instruction after the jmp
    *pre_backup_addr = tramp;

    memcpy(tramp, post_backup, sizeof(post_backup));
    tramp += sizeof(post_backup);

    // return the length of this trampoline
    return tramp - base;
}

// this function constructs the so-called pre-trampoline, this pre-trampoline
// determines if a hook should really be executed. An example will be the
// easiest; imagine we have a hook on CreateProcessInternalW() and on
// NtCreateProcessEx() (this is actually the case currently), now, if all goes
// well, a call to CreateProcess() will call CreateProcessInternalW() followed
// by a call to NtCreateProcessEx(). Because we already hook the higher-level
// API CreateProcessInternalW() it is not really useful to us to log the
// information retrieved in the NtCreateProcessEx() function as well,
// therefore, because one is called by the other, we can tell the hooking
// engine "once inside a hook, don't hook further API calls" by setting the
// allow_hook_recursion flag to false. The example above is what happens when
// the hook recursion is not allowed.
static void hook_create_pre_tramp(hook_t *h, uint8_t is_special_hook)
{
    unsigned char pre_tramp[] = {
        // push ebx
        0x53,
        // push eax
        0x50,

        // mov eax, fs:[TLS_HOOK_INFO]
        0x64, 0xa1, TLS_HOOK_INFO, 0x00, 0x00, 0x00,
        // test eax, eax
        0x85, 0xc0,
        // jnz $+0d
        0x75, 0x0d,
            // pushad
            0x60,
            // call ensure_valid_hook_info
            0xe8, 0x00, 0x00, 0x00, 0x00,
            // popad
            0x61,
            // mov eax, fs:[TLS_HOOK_INFO]
            0x64, 0xa1, TLS_HOOK_INFO, 0x00, 0x00, 0x00,

        // inc dword [eax+hook_info_t.depth_count]
        0xff, 0x40, offsetof(hook_info_t, depth_count),

        // mov ebx, [esp+8]
        0x8b, 0x5c, 0xe4, 0x08,
        // xchg esp, [eax+hook_info_t.retaddr_esp]
        0x87, 0x60, offsetof(hook_info_t, retaddr_esp),
        // push ebx
        0x53,
        // xchg esp, [eax+hook_info_t.retaddr_esp]
        0x87, 0x60, offsetof(hook_info_t, retaddr_esp),
        // mov dword [esp+8], new_return_address
        0xc7, 0x44, 0xe4, 0x08, 0x00, 0x00, 0x00, 0x00,

        // special hook support
        // mov ebx, 1
        0xbb, 0x01, 0x00, 0x00, 0x00,
        // cmp ebx, is_special_hook
        0x83, 0xfb, is_special_hook,
        // jnz $+7
        0x75, 0x07,
            // pop eax; pop ebx
            0x58, 0x5b,
            // jmp h->store_exc
            0xe9, 0x00, 0x00, 0x00, 0x00,

        // cmp dword [eax+hook_info_t.depth_count], 1
        0x83, 0x78, offsetof(hook_info_t, depth_count), 0x01,
        // jle $+7
        0x7e, 0x07,
            // pop eax; pop ebx
            0x58, 0x5b,
            // jmp h->tramp
            0xe9, 0x00, 0x00, 0x00, 0x00,

        // pushad
        0x60,
        // push ebp
        0x55,
        // call is_interesting_backtrace
        0xe8, 0x00, 0x00, 0x00, 0x00,
        // test eax, eax
        0x85, 0xc0,
        // pop eax
        0x58,
        // popad
        0x61,
        // jnz $+7
        0x75, 0x07,
            // pop eax; pop ebx
            0x58, 0x5b,
            // jmp h->tramp
            0xe9, 0x00, 0x00, 0x00, 0x00,

        // pop eax; pop ebx
        0x58, 0x5b,
        // jmp h->store_exc
        0xe9, 0x00, 0x00, 0x00, 0x00,


        // push ebx; push eax
        0x53, 0x50,
        // mov eax, fs:[TLS_HOOK_INFO]
        0x64, 0xa1, TLS_HOOK_INFO, 0x00, 0x00, 0x00,
        // dec dword [eax+hook_info_t.depth_count]
        0xff, 0x48, offsetof(hook_info_t, depth_count),
        // push dword [eax+hook_info_t.last_error]
        0xff, 0x70, offsetof(hook_info_t, last_error),
        // pop dword fs:[0x34]
        0x64, 0x8f, 0x05, 0x34, 0x00, 0x00, 0x00,

        // xchg esp, [eax+hook_info_t.retaddr_esp]
        0x87, 0x60, offsetof(hook_info_t, retaddr_esp),
        // pop ebx
        0x5b,
        // xchg esp, [eax+hook_info_t.retaddr_esp]
        0x87, 0x60, offsetof(hook_info_t, retaddr_esp),
        // pop eax
        0x58,
        // xchg ebx, dword [esp]
        0x87, 0x1c, 0xe4,
        // retn
        0xc3,

    };

    *(unsigned int *)(pre_tramp + 14) =
        (unsigned char *) &ensure_valid_hook_info - h->pre_tramp - 13 - 5;
    *(unsigned int *)(pre_tramp + 43) = (unsigned int) h->pre_tramp + 104;

    *(unsigned int *)(pre_tramp + 60) =
        (unsigned char *) h->store_exc - h->pre_tramp - 59 - 5;

    *(unsigned int *)(pre_tramp + 73) = h->tramp - h->pre_tramp - 72 - 5;
    *(unsigned int *)(pre_tramp + 80) =
        (unsigned char *) &is_interesting_backtrace - h->pre_tramp - 79 - 5;
    *(unsigned int *)(pre_tramp + 93) = h->tramp - h->pre_tramp - 92 - 5;
    *(unsigned int *)(pre_tramp + 100) =
        (unsigned char *) h->store_exc - h->pre_tramp - 99 - 5;

    memcpy(h->pre_tramp, pre_tramp, sizeof(pre_tramp));
}

static void hook_store_exception_info(hook_t *h)
{
    unsigned char store_exception[] = {
        // push eax
        0x50,
        // mov eax, fs:[TLS_HOOK_INFO]
        0x64, 0xa1, TLS_HOOK_INFO, 0x00, 0x00, 0x00,
        // xchg ebx, dword [esp]
        0x87, 0x1c, 0xe4,
        // mov dword [eax+hook_info_t.eax], ebx
        0x89, 0x58, offsetof(hook_info_t, eax),
        // xchg ebx, dword [esp]
        0x87, 0x1c, 0xe4,
        // mov dword [eax+hook_info_t.ecx], ecx
        0x89, 0x48, offsetof(hook_info_t, ecx),
        // mov dword [eax+hook_info_t.edx], edx
        0x89, 0x50, offsetof(hook_info_t, edx),
        // mov dword [eax+hook_info_t.ebx], ebx
        0x89, 0x58, offsetof(hook_info_t, ebx),
        // mov dword [eax+hook_info_t.esp], esp
        0x89, 0x60, offsetof(hook_info_t, esp),
        // mov dword [eax+hook_info_t.ebp], ebp
        0x89, 0x68, offsetof(hook_info_t, ebp),
        // mov dword [eax+hook_info_t.esi], esi
        0x89, 0x70, offsetof(hook_info_t, esi),
        // mov dword [eax+hook_info_t.edi], edi
        0x89, 0x78, offsetof(hook_info_t, edi),
        // pop eax
        0x58,
        // jmp h->new_func
        0xe9, 0x00, 0x00, 0x00, 0x00,
    };

    unsigned int offset = sizeof(store_exception) - 5;
    *(unsigned int *)(store_exception + offset + 1) =
            (unsigned char *) h->new_func - h->store_exc - offset - 5;
    memcpy(h->store_exc, store_exception, sizeof(store_exception));
}

static int hook_api_jmp_direct(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // unconditional jump opcode
    *from = 0xe9;

    // store the relative address from this opcode to our hook function
    *(unsigned long *)(from + 1) = (unsigned char *) to - from - 5;
    return 0;
}

static int hook_api_nop_jmp_direct(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // nop
    *from++ = 0x90;

    return hook_api_jmp_direct(h, from, to);
}

static int hook_api_hotpatch_jmp_direct(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov edi, edi
    *from++ = 0x8b;
    *from++ = 0xff;

    return hook_api_jmp_direct(h, from, to);
}

static int hook_api_push_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // push addr
    *from++ = 0x68;
    *(unsigned char **) from = to;

    // retn
    from[4] = 0xc3;

    return 0;
}

static int hook_api_nop_push_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // nop
    *from++ = 0x90;

    return hook_api_push_retn(h, from, to);
}

static int hook_api_jmp_indirect(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // jmp dword [hook_data]
    *from++ = 0xff;
    *from++ = 0x25;

    *(unsigned char **) from = h->hook_data;

    // the real address is stored in hook_data
    memcpy(h->hook_data, &to, sizeof(to));
    return 0;
}

static int hook_api_mov_eax_jmp_eax(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov eax, address
    *from++ = 0xb8;
    *(unsigned char **) from = to;
    from += 4;

    // jmp eax
    *from++ = 0xff;
    *from++ = 0xe0;
    return 0;
}

static int hook_api_mov_eax_push_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov eax, address
    *from++ = 0xb8;
    *(unsigned char **) from = to;
    from += 4;

    // push eax
    *from++ = 0x50;

    // retn
    *from++ = 0xc3;
    return 0;
}

static int hook_api_mov_eax_indirect_jmp_eax(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov eax, [hook_data]
    *from++ = 0xa1;
    *(unsigned char **) from = h->hook_data;
    from += 4;

    // store the address at hook_data
    memcpy(h->hook_data, &to, sizeof(to));

    // jmp eax
    *from++ = 0xff;
    *from++ = 0xe0;
    return 0;
}

static int hook_api_mov_eax_indirect_push_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // mov eax, [hook_data]
    *from++ = 0xa1;
    *(unsigned char **) from = h->hook_data;
    from += 4;

    // store the address at hook_data
    memcpy(h->hook_data, &to, sizeof(to));

    // push eax
    *from++ = 0x50;

    // retn
    *from++ = 0xc3;
    return 0;
}

#if HOOK_ENABLE_FPU
static int hook_api_push_fpu_retn(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // push ebp
    *from++ = 0x55;

    // fld qword [hook_data]
    *from++ = 0xdd;
    *from++ = 0x05;

    *(unsigned char **) from = h->hook_data;
    from += 4;

    // fistp dword [esp]
    *from++ = 0xdb;
    *from++ = 0x1c;
    *from++ = 0xe4;

    // retn
    *from++ = 0xc3;

    // store the address as double
    double addr = (double) (unsigned long) to;
    memcpy(h->hook_data, &addr, sizeof(addr));
    return 0;
}
#endif

static int hook_api_special_jmp(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // our largest hook in use is currently 7 bytes. so we have to make sure
    // that this special hook (a hook that will be patched over again later)
    // is atleast seven bytes.
    *from++ = 0x90;
    *from++ = 0x90;
    return hook_api_jmp_direct(h, from, to);
}

int hook_api(hook_t *h, int type)
{
    // table with all possible hooking types
    static struct {
        int(*hook)(hook_t *h, unsigned char *from, unsigned char *to);
        int len;
    } hook_types[] = {
        /* HOOK_JMP_DIRECT */ {&hook_api_jmp_direct, 5},
        /* HOOK_NOP_JMP_DIRECT */ {&hook_api_nop_jmp_direct, 6},
        /* HOOK_HOTPATCH_JMP_DIRECT */ {&hook_api_hotpatch_jmp_direct, 7},
        /* HOOK_PUSH_RETN */ {&hook_api_push_retn, 6},
        /* HOOK_NOP_PUSH_RETN */ {&hook_api_nop_push_retn, 7},
        /* HOOK_JMP_INDIRECT */ {&hook_api_jmp_indirect, 6},
        /* HOOK_MOV_EAX_JMP_EAX */ {&hook_api_mov_eax_jmp_eax, 7},
        /* HOOK_MOV_EAX_PUSH_RETN */ {&hook_api_mov_eax_push_retn, 7},
        /* HOOK_MOV_EAX_INDIRECT_JMP_EAX */
            {&hook_api_mov_eax_indirect_jmp_eax, 7},
        /* HOOK_MOV_EAX_INDIRECT_PUSH_RETN */
            {&hook_api_mov_eax_indirect_push_retn, 7},
#if HOOK_ENABLE_FPU
        /* HOOK_PUSH_FPU_RETN */ {&hook_api_push_fpu_retn, 11},
#endif
        /* HOOK_SPECIAL_JMP */ {&hook_api_special_jmp, 7},
    };

    // is this address already hooked?
    if(h->is_hooked != 0) {
        return 0;
    }

    // resolve the address to hook
    unsigned char *addr = h->addr;

    if(addr == NULL && h->library != NULL && h->funcname != NULL) {
        addr = (unsigned char *) GetProcAddress(GetModuleHandleW(h->library),
            h->funcname);
    }
    if(addr == NULL) {
        return -1;
    }

    int ret = -1;

    // check if this is a valid hook type
    if(type >= 0 && type < ARRAYSIZE(hook_types)) {

        // determine whether we're running under win7, if so, we might have to
        // follow a short relative jmp and an indirect jump before reaching
        // the real address
        OSVERSIONINFO os_info = {sizeof(OSVERSIONINFO)};
        if(GetVersionEx(&os_info) && os_info.dwMajorVersion == 6 &&
                os_info.dwMinorVersion == 1) {
            // windows 7 has a DLL called kernelbase.dll which basically acts
            // as a layer between the program and kernel32 (and related?) it
            // allows easy hotpatching of a set of functions which is why
            // there's a short relative jump and an indirect jump. we want to
            // resolve the address of the real function, so we follow these
            // two jumps.
            if(!memcmp(addr, "\xeb\x05", 2) &&
                    !memcmp(addr + 7, "\xff\x25", 2)) {
                addr = **(unsigned char ***)(addr + 9);
            }

            // Some functions don't just have the short jump and indirect
            // jump, but also an empty function prolog
            // ("mov edi, edi ; push ebp ; mov ebp, esp ; pop ebp"). Other
            // than that, this edge case is equivalent to the case above.
            else if(!memcmp(addr, "\x8b\xff\x55\x8b\xec\x5d\xeb\x05", 8) &&
                    !memcmp(addr + 13, "\xff\x25", 2)) {
                addr = **(unsigned char ***)(addr + 15);
            }

            // the following applies for "inlined" functions on windows 7,
            // some functions are inlined into kernelbase.dll, rather than
            // kernelbase.dll jumping to e.g. kernel32.dll. for these
            // functions there is a short relative jump, followed by the
            // inlined function.
            if(!memcmp(addr, "\xeb\x02", 2) &&
                    !memcmp(addr - 5, "\xcc\xcc\xcc\xcc\xcc", 5)) {
                // step over the short jump and the relative offset
                addr += 4;
            }
        }

        DWORD old_protect;

        // make the address writable
        if(VirtualProtect(addr, hook_types[type].len, PAGE_EXECUTE_READWRITE,
                &old_protect)) {

            if(hook_create_trampoline(addr, hook_types[type].len, h->tramp)) {

                hook_store_exception_info(h);

                uint8_t special = 0;

                if(h->allow_hook_recursion == 1) {
                    special = 1;
                }

                hook_create_pre_tramp(h, special);

                // insert the hook (jump from the api to the
                // pre-trampoline)
                ret = hook_types[type].hook(h, addr, h->pre_tramp);

                // if successful, assign the trampoline address to *old_func
                if(ret == 0) {
                    *h->old_func = h->tramp;

                    // successful hook is successful
                    h->is_hooked = 1;
                }
            }

            // restore the old protection
            VirtualProtect(addr, hook_types[type].len, old_protect,
                &old_protect);
        }
    }

    return ret;
}

hook_info_t *hook_info()
{
    return (hook_info_t *) __readfsdword(TLS_HOOK_INFO);
}

static void ensure_valid_hook_info()
{
    if(hook_info() == NULL) {
        hook_info_t *info = (hook_info_t *) calloc(1, sizeof(hook_info_t)+TLS_HOOK_INFO_RETADDR_SPACE);
        info->retaddr_esp = (unsigned int) info + sizeof(hook_info_t) + TLS_HOOK_INFO_RETADDR_SPACE;
        __writefsdword(TLS_HOOK_INFO, (unsigned int) info);
    }
}

void hook_enable()
{
    ensure_valid_hook_info();
    hook_info()->depth_count--;
}

void hook_disable()
{
    ensure_valid_hook_info();
    hook_info()->depth_count++;
}

int hook_is_inside()
{
    ensure_valid_hook_info();
    return hook_info()->depth_count || hook_info()->hook_count;
}

unsigned int hook_get_last_error()
{
    ensure_valid_hook_info();
    return hook_info()->last_error;
}

void hook_set_last_error(unsigned int errcode)
{
    ensure_valid_hook_info();
    hook_info()->last_error = errcode;
}

void hook_disable_retaddr_check()
{
    g_enable_retaddr_check = 0;
}
