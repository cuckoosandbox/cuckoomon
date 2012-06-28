#include <stdio.h>
#include "../log.h"

int main()
{
    loq("2s", "a", "b", "c", "d");
    loq("S", "a", 4, "hello");
    loq("U", "b", 4, L"ab\u1337c");
    loq("s", "c", NULL);
}
