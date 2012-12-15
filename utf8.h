
int utf8_encode(unsigned short x, unsigned char *out);
int utf8_length(unsigned short x);

// name is a bit weird.. but it calculates the length of the utf8 encoded
// unicode string "s" in bytes
int utf8_strlen_unicode(const wchar_t *s, int len);
