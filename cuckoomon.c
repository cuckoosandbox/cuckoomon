#include <stdio.h>
#include <windows.h>

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if(dwReason == DLL_PROCESS_ATTACH) {
        // do stuff
    }
    return TRUE;
}
