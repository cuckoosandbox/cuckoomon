#include <stdio.h>
#include "../log.h"

int main()
{
    loq("2s", "a", "b", "c", "d");
    loq("S", "a", 4, "hello");
    loq("U", "b", 4, L"ab\u1337c");
    loq("s", "c", NULL);
    loq("lUl", "a", 32, "b", 6, L"HelloWorld", "c", 32);

    // utf8 encoding examples from wikipedia, should result in the following:
    // "\x24\xc2\xa2\xe2\x82\xac"
    loq("u", "a", L"\u0024\u00a2\u20ac");

    int argc = 4;
    char *argv[] = {"a", "b", "c", "d"};
    loq("a", "a", argc, argv);
}
