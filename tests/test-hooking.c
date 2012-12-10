#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "../hooking.h"

#define COUNT 8
#define SIZE 64

// the code of the functions
unsigned char g_functions[COUNT][SIZE] = {
    // normal function; push ebp ; mov ebp, esp ; sub esp, 0x40
    {0x55, 0x89, 0xe5, 0x83, 0xec, 0x40},
    // hooked function; jmp 0x44332211
    {0xe9, 0xcc, 0x21, 0x31, 0x44},
    // winapi with hot-patching; mov edi, edi ; push ebp ; mov ebp, esp
    {0x8b, 0xff, 0x55, 0x8b, 0xec},
};

// the length of the required hook codes
unsigned char g_function_lengths[] = {
    5, 5, 5
};

unsigned char gate_solutions[COUNT][SIZE] = {
    {0x55, 0x89, 0xe5, 0x83, 0xec, 0x40, 0xe9, 0xfb, 0xef, 0xff, 0xff},
    {0xe9, 0xcc, 0x11, 0x31, 0x44, 0xe9, 0xfb, 0xef, 0xff, 0xff},
    {0x8b, 0xff, 0x55, 0x8b, 0xec, 0xe9, 0xfb, 0xef, 0xff, 0xff},
};

int main()
{
    // we allocate one memory pages, because globals have different addresses
    // based on compiler/settings (addresses are still relative to each other
    // so the base address is not important)
    unsigned char *functions = (unsigned char *) VirtualAlloc(NULL, 0x3000,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    unsigned char *gates = functions + 0x1000;
    hook_t *hook = (hook_t *)(functions + 0x2000);

    if(functions == NULL) {
        printf("Error allocating memory..\n");
        return 0;
    }

    memcpy(functions, g_functions, sizeof(g_functions));

    // create and check callgates
    for (int i = 0; i < COUNT && functions[i * SIZE] != 0; i++) {
        int len = hook_create_trampoline(&functions[i * SIZE],
            g_function_lengths[i], &gates[i * SIZE]);
        if(memcmp(&gates[i * SIZE], gate_solutions[i], SIZE)) {
            printf("%dth gate is invalid!\n", i);
            for (int j = 0; j < len; j++) {
                printf("%02x %02x\n", gates[i * SIZE + j],
                    gate_solutions[i][j]);
            }
            return 0;
        }
    }

    memset(gates, 0, 0x1000);
    memset(hook, 0, 0x1000);

    // make a hook which hooks the first function and uses the second function
    // as hook address
    void *old_addr;
    hook->addr = functions;
    hook->new_func = &functions[SIZE];
    hook->old_func = &old_addr;

    hook_api(hook, HOOK_JMP_DIRECT);
    if(memcmp(functions, "\xe9\x3b\x00\x00\x00\x40", 6) || memcmp(hook->tramp,
            "\x55\x89\xe5\x83\xec\x40\xe9\xe7\xdf\xff\xff", 11)) {
        printf("Invalid first hook!\n");
        return 0;
    }

    printf("all tests were successful!\n");
}
