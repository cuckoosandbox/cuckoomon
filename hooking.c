#include <stdio.h>
#include <windows.h>
#include "hooking.h"
#include "distorm.h"
#include "mnemonics.h"

_DecodeResult (*lp_distorm_decompose)(_CodeInfo* ci, _DInst result[],
    unsigned int maxInstructions, unsigned int* usedInstructionsCount);

static void hook_init()
{
    static int first = 0;
    if(first) return;
    first = 1;

    *(FARPROC *) &lp_distorm_decompose = GetProcAddress(
        LoadLibrary("distorm3.dll"), "distorm_decompose64");
}

// length disassembler engine
int lde(void *addr)
{
    hook_init();

    // the length of an instruction is 16 bytes max, but there can also be
    // 16 instructions of length one, so.. we support "decomposing" 16
    // instructions at once, max
    unsigned int used_instruction_count; _DInst instructions[16];
    _CodeInfo code_info = {0, 0, addr, 16, Decode32Bits};
    _DecodeResult ret = lp_distorm_decompose(&code_info, instructions, 16,
        &used_instruction_count);

    return ret == DECRES_SUCCESS ? instructions[0].size : 0;
}

// direct 0xe9 jmp
static int hook_api_jmp_direct(hook_t *h)
{
    FARPROC addr = GetProcAddress(GetModuleHandle(h->library), h->funcname);
    if(addr == NULL) return 0;

    DWORD old_protect;
    if(VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
        unsigned char *p = (unsigned char *) addr;

        // TODO make a backup of the first few instructions
        // ...

        // jmp opcode
        *p = 0xe9;

        // store the relative address from this opcode to our hook function
        *(unsigned long *)(p + 1) = (unsigned char *) h->new_func - p - 5;
        return 1;
    }
    return 0;
}

int hook_api(hook_t *h)
{
    // default hooking type at the moment
    return hook_api_jmp_direct(h);
}

