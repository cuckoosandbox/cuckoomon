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
#include "hooking.h"
#include "distorm.h"
#include "mnemonics.h"
#include "ntapi.h"
#include "distorm.h"

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

// create a `callgate' at the given address, that is, we are going to replace
// the original instructions at this particular address. So, in order to
// call the original function from our hook, we have to execute the original
// instructions *before* jumping into addr+offset, where offset is the length
// which totals the size of the instructions which we place in the `gate'.
// returns 0 on failure, or a positive integer defining the size of the gate
// NOTE: gate represents the real memory where the callgate will be placed
// copying it to another location will result into failure
int hook_create_callgate(unsigned char *addr, int len, unsigned char *gate)
{
    const unsigned char *base = gate;

    // after the original function has returned, we have to make a backup of
    // the Last Error Code, so what we do is the following (we use the same
    // method below in the pre-gate.) We store the current return address in
    // fs:[0x50], we overwrite it with a return address in our gate. When we
    // reach the gate, then we make a backup of the Last Error Code and jmp
    // to the real return address.

    unsigned char pre_backup[] = {
        // cmp dword fs:[0x44], 1 (check if we are already inside a hook, the
        // cmp dword fs:[0x54], 0 (check if we are already inside a hook, the
        // next few instructions only apply to the first hook)
        0x64, 0x83, 0x3d, 0x54, 0x00, 0x00, 0x00, 0x00,
        // jg $+18 (if we are already inside a hook, then we don't want to
        // replace the return address, so jump over the next few instructions)
        0x7f, 0x18,
        // inc dword fs:[0x54] (increase the hook count, why not zoidberg?)
        0x64, 0xff, 0x05, 0x54, 0x00, 0x00, 0x00,
        // push dword [esp] (obtain the current return address)
        0xff, 0x34, 0xe4,
        // pop dword fs:[0x50] (store the return address in the TIB)
        0x64, 0x8f, 0x05, 0x50, 0x00, 0x00, 0x00,
        // mov dword [esp], new_return_address (overwrite the return address)
        0xc7, 0x04, 0xe4, 0x00, 0x00, 0x00, 0x00,
    };

    memcpy(gate, pre_backup, sizeof(pre_backup));
    gate += sizeof(pre_backup);

    unsigned char **pre_backup_addr = (unsigned char **)(gate - 4);

    // our gate should be atleast contain enough bytes to fit the given length
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
        // gate

        // it's a (conditional) jump or call with 32bit relative offset
        if(*addr == 0xe9 || *addr == 0xe8 || (*addr == 0x0f &&
                addr[1] >= 0x80 && addr[1] < 0x90)) {

            // copy the jmp or call instruction (conditional jumps are two
            // bytes, the rest is one byte)
            *gate++ += *addr++;
            if(addr[-1] != 0xe9 && addr[-1] != 0xe8) {
                *gate++ += *addr++;
            }

            // when a jmp/call is performed, then the relative offset +
            // the instruction pointer + the size of the instruction is the
            // calculated address, so that's our target address as well.
            // (note that `addr' is already increased by one or two, so the
            // 4 represents the 32bit offset of this particular instruction)
            unsigned long jmp_addr = *(unsigned long *) addr + 4 +
                (unsigned long) addr;
            addr += 4;

            // gate is already filled with the opcode itself (the jump
            // instruction), now we will actually jump to the location by
            // calculating the relative offset which points to the real
            // address (this is the reverse operation of the one to calculate
            // the absolute address of a jump)
            *(unsigned long *) gate = jmp_addr - (unsigned long) gate - 4;
            gate += 4;

            // because an unconditional jump denotes the end of a basic block
            // we will return failure if we have not yet processed enough room
            // to store our hook code
            if(gate[-5] == 0xe9 && len > 0) return 0;
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
            // a jump from the gate to the original function, so instead we
            // will use 32bit relative offset jumps
            if(*addr == 0xeb) {
                *gate++ = 0xe9;
            }
            else {
                // hex representation of the two types of 32bit jumps
                // 8bit relative conditional jumps:     70..80
                // 32bit relative conditional jumps: 0f 80..90
                // so we will simply add 0x10 to the opcode of 8bit relative
                // offset jump to obtain the 32bit relative offset jump opcode
                *gate++ = 0x0f;
                *gate++ = *addr + 0x10;
            }

            // calculate the correct relative offset address
            *(unsigned long *) gate = jmp_addr - (unsigned long) gate - 4;
            gate += 4;

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
            // copy the instruction directly to the gate
            while (length-- != 0) {
                *gate++ = *addr++;
            }
        }
    }

    // append a jump from the gate to the original function
    *gate++ = 0xe9;
    *(unsigned long *) gate = (unsigned long) addr - (unsigned long) gate - 4;
    gate += 4;

    // return address is the next instruction after the jmp
    *pre_backup_addr = gate;

    // the function returns here after executing, backup the Last Error Code
    unsigned char post_backup[] = {
        // dec dword fs:[0x54] (decrease the hook count)
        0x64, 0xff, 0x0d, 0x54, 0x00, 0x00, 0x00,
        // push dword fs:[0x34]
        0x64, 0xff, 0x35, 0x34, 0x00, 0x00, 0x00,
        // pop dword fs:[0x4c]
        0x64, 0x8f, 0x05, 0x4c, 0x00, 0x00, 0x00,
        // jmp dword fs:[0x50] (jmp to the real return address)
        0x64, 0xff, 0x25, 0x50, 0x00, 0x00, 0x00,
    };

    memcpy(gate, post_backup, sizeof(post_backup));
    gate += sizeof(post_backup);

    // return the length of this gate
    return gate - base;
}

// this function constructs the so-called pre-gate, this pre-gate determines
// if a hook should really be executed. An example will be the easiest;
// imagine we have a hook on CreateProcessInternalW() and on
// NtCreateProcessEx() (this is actually the case currently), now, if all goes
// well, a call to CreateProcess() will call CreateProcessInternalW() followed
// by a call to NtCreateProcessEx(). Because we already hook the higher-level
// API CreateProcessInternalW() it is not really useful to us to log the
// information retrieved in the NtCreateProcessEx() function as well,
// therefore, because one is called by the other, we can tell the hooking
// engine "once inside a hook, don't hook further API calls" by setting the
// allow_hook_recursion flag to false. The example above is what happens when
// the hook recursion is not allowed.
void hook_create_pre_gate(hook_t *h)
{
    // we store the depth count in fs:[0x44] and a temporary return address in
    // fs:[0x48] (we have to store it somewhere, so TIB is the best place..)

    unsigned char sc[] = {
        // cmp dword fs:[0x44], 0 (check if we are already inside a hook)
        0x64, 0x83, 0x3d, 0x44, 0x00, 0x00, 0x00, 0x00,
        // jle $+5 (jump over the following 32bit relative offset jump if we
        // are note already inside a hook)
        0x7e, 0x05,
        // jmp h->gate (we do not hook this call, jump to the gate)
        0xe9, 0x00, 0x00, 0x00, 0x00,
        // inc dword fs:[0x44] (increase the hook count)
        0x64, 0xff, 0x05, 0x44, 0x00, 0x00, 0x00,
        // we temporarily store the current return address in fs:[0x48]
        // because we have to alter it, in order to return to this pre-gate
        // so we can decrement the hook count
        // push dword [esp] (obtain the current return address)
        0xff, 0x34, 0xe4,
        // pop dword fs:[0x48] (store the return address in the TIB)
        0x64, 0x8f, 0x05, 0x48, 0x00, 0x00, 0x00,
        // mov dword [esp], new_return_address (overwrite the return address)
        0xc7, 0x04, 0xe4, 0x00, 0x00, 0x00, 0x00,
        // jmp h->new_func (we hook this call, jump to the new function)
        0xe9, 0x00, 0x00, 0x00, 0x00,
        // this is where the new_return_address is located..
        // dec dword fs:[0x44] (decrease the hook count)
        0x64, 0xff, 0x0d, 0x44, 0x00, 0x00, 0x00,
        // push dword fs:[0x4c] (restore the Last Error Code)
        0x64, 0xff, 0x35, 0x4c, 0x00, 0x00, 0x00,
        // pop dword fs:[0x34]
        0x64, 0x8f, 0x05, 0x34, 0x00, 0x00, 0x00,
        // jmp dword fs:[0x48] (jmp to the real return address)
        0x64, 0xff, 0x25, 0x48, 0x00, 0x00, 0x00,
    };

    *(unsigned long *)(sc + 11) = h->gate - h->pre_gate - 10 - 5;
    *(unsigned long *)(sc + 35) = (unsigned long) h->pre_gate + 44;
    *(unsigned long *)(sc + 40) =
        (unsigned char *) h->new_func - h->pre_gate - 39 - 5;

    memcpy(h->pre_gate, sc, sizeof(sc));
}

// direct 0xe9 jmp
static int hook_api_jmp_direct(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // unconditional jump opcode
    *from = 0xe9;

    // store the relative address from this opcode to our hook function
    *(unsigned long *)(from + 1) = (unsigned char *) to - from - 5;
    return 0;
}

// useful for "detections" such as if(*api_addr == 0xe9)
static int hook_api_nop_jmp_direct(hook_t *h, unsigned char *from,
    unsigned char *to)
{
    // nop
    *from++ = 0x90;

    return hook_api_jmp_direct(h, from, to);
}

// useful for "detections" such as if(*api_addr == 0xe9)
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
    return 1;
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
    return 1;
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
    return 1;
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
    return 1;
}

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
        /* HOOK_JMP_INDIRECT */ {&hook_api_jmp_indirect, 6},
        /* HOOK_MOV_EAX_JMP_EAX */ {&hook_api_mov_eax_jmp_eax, 7},
        /* HOOK_MOV_EAX_PUSH_RETN */ {&hook_api_mov_eax_push_retn, 7},
        /* HOOK_MOV_EAX_INDIRECT_JMP_EAX */
            {&hook_api_mov_eax_indirect_jmp_eax, 7},
        /* HOOK_MOV_EAX_INDIRECT_PUSH_RETN */
            {&hook_api_mov_eax_indirect_push_retn, 7},
        /* HOOK_PUSH_FPU_RETN */ {&hook_api_push_fpu_retn, 11},
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

            if(hook_create_callgate(addr, hook_types[type].len, h->gate)) {

                // if allow hook recursion is *not* set, then we have to
                // create a pre-gate
                if(h->allow_hook_recursion == 0) {
                    hook_create_pre_gate(h);

                    // insert the hook (jump from the api to the pre-gate)
                    ret = hook_types[type].hook(h, addr, h->pre_gate);
                }
                else {
                    // insert the hook (jump from the api to the new function)
                    ret = hook_types[type].hook(h, addr, h->new_func);
                }

                // if successful, assign the gate address to *old_func
                if(ret == 0) {
                    *h->old_func = h->gate;

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

void hook_enable()
{
    __asm__("decl %%fs:(%0)" :: "r" (0x44));
}

void hook_disable()
{
    __asm__("incl %%fs:(%0)" :: "r" (0x44));
}

unsigned int hook_get_last_error()
{
    unsigned int lasterr;
    __asm__("movl %%fs:(%1), %0" : "=r" (lasterr) : "r" (0x4c));
    return lasterr;
}

void hook_set_last_error(unsigned int errcode)
{
    __asm__("movl %1, %%fs:(%0)" :: "r" (0x4c), "r" (errcode));
}
