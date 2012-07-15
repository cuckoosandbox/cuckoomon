#include <stdio.h>
#include <windows.h>
#include <direct.h>

int main()
{
    LoadLibrary("../cuckoomon.dll");

    _mkdir("abc");
}
