#include <stdio.h>
#include <windows.h>
#include "../log.h"

const char *module_name = "logging";

int main()
{
    int is_success(int ret) { return 1; }
    int ret = 0;

    log_init(0, 0, 1);

    LOQ("2s", "a", "b", "c", "d");
    LOQ("S", "a", 4, "hello");
    LOQ("U", "b", 4, L"ab\u1337c");
    LOQ("s", "c", NULL);
    LOQ("lUl", "a", 32, "b", 6, L"HelloWorld", "c", 32);

    // utf8 encoding examples from wikipedia, should result in the following:
    // "\x24\xc2\xa2\xe2\x82\xac"
    LOQ("u", "a", L"\u0024\u00a2\u20ac");

    int argc = 4;
    char *argv[] = {"a", "b", "c", "d"};
    LOQ("a", "a", argc, argv);

    // registry stuff
    LOQ("r", "a", REG_SZ, 0, "lolz");
    LOQ("r", "a", REG_DWORD, 4, "\x10\x00\x00\x00");
    LOQ("R", "a", REG_SZ, 1337, L"omgz0r");
    LOQ("R", "a", REG_BINARY, 8, "Hello World");
}
