#include <stdio.h>

//
// Log API
//

void log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    while (*fmt) {
    }
    va_end(args);
}
