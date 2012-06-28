#include <stdio.h>

//
// Log API
//

void log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int count = 1; char key, nokey;
    while (*fmt) {
        // we have to find the next format specifier
        if(--count == 0) {
            // end of format
            if(*fmt == 0) break;

            // repeat format specifier
            if(*fmt >= '2' && *fmt < '9') {
                count = *fmt++ - '0';
            }

            // the next format specifier
            key = *fmt++;

            // omit the key?
            nokey = 0;
            if(*fmt == '!') {
                nokey = 1, fmt++;
            }
        }

        // ...
    }
    va_end(args);
}
