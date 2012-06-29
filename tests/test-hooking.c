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
    {0x55, 0x89, 0xe5, 0x83, 0xec, 0x40, 0xe9, 0xfb, 0xff, 0xfe, 0xff},
    {0xe9, 0xcc, 0x21, 0x30, 0x44, 0xe9, 0xfb, 0xff, 0xfe, 0xff},
    {0x8b, 0xff, 0x55, 0x8b, 0xec, 0xe9, 0xfb, 0xff, 0xfe, 0xff},
};

int main()
{
    // we allocate two memory pages, because globals have different addresses
    // based on compiler/settings
    unsigned char *functions = (unsigned char *) VirtualAlloc(
        (void *) 0x20000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    unsigned char *gates = (unsigned char *) VirtualAlloc(
        (void *) 0x30000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    memcpy(functions, g_functions, sizeof(g_functions));

    for (int i = 0; i < COUNT; i++) {
        int len = hook_create_callgate(&functions[i * SIZE],
            g_function_lengths[i], &gates[i * SIZE]);
        if(memcmp(&gates[i * SIZE], gate_solutions[i], SIZE)) {
            printf("%dth gate is invalid!\n", i);
            for (int j = 0; j < len; j++) {
                printf("%02x %02x\n", gates[i * SIZE + j],
                    gate_solutions[i][j]);
            }
        }
    }
}
