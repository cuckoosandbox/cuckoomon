#include <stdio.h>
#include <windows.h>
#include "utf8.h"

int utf8_encode(unsigned short c, unsigned char *out)
{
    if(c < 0x80) {
        *out = c & 0x7f;
        return 1;
    }
    else if(c < 0x800) {
        *out = 0xc0 + ((c >> 8) << 2) + (c >> 6);
        out[1] = 0x80 + (c & 0x3f);
        return 2;
    }
    else {
        *out = 0xe0 + (c >> 12);
        out[1] = 0x80 + (((c >> 8) & 0x1f) << 2) + ((c >> 6) & 0x3);
        out[2] = 0x80 + (c & 0x3f);
        return 3;
    }
}

int utf8_length(unsigned short x)
{
    unsigned char buf[3];
    return utf8_encode(x, buf);
}

int utf8_strlen_unicode(const wchar_t *s, int len)
{
    if(len < 0) len = lstrlenW(s);

    int ret = 0;
    while (len-- != 0) {
        ret += utf8_length(*s++);
    }
    return ret;
}
