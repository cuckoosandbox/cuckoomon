#include <stdio.h>
#include <windows.h>

int main()
{
    LoadLibrary("../cuckoomon.dll");

    printf("hoi: %p\n", GetProcAddress(LoadLibrary("advapi32.dll"),
            "RegQueryValueExW"));
}
