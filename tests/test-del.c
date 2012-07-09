#include <stdio.h>
#include <windows.h>

int main()
{
    LoadLibrary("../cuckoomon.dll");

    DeleteFileW(L"hoi");
}
