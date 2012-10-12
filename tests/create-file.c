#include <stdio.h>
#include <windows.h>

/* http://linux.die.net/man/3/fopen */

int main()
{
    // reading + writing, cur_start
    fclose(fopen("a", "r+"));

    // truncate file for writing, cur_start
    fclose(fopen("b", "w"));

    // truncate file for reading + writing, cur_start
    fclose(fopen("c", "w+"));

    // open for writing, cur_end
    fclose(fopen("d", "a"));

    // open for reading + writing, reading = cur_start, writing = cur_end
    fclose(fopen("e", "a+"));
}
