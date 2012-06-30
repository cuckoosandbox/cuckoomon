
//
// Log API
//
// The Log takes a format string and parses the extra arguments accordingly
//
// The following Format Specifiers are available:
// s  -> (char *) -> zero-terminated string
// S  -> (int, char *) -> string with length
// u  -> (wchar_t *) -> zero-terminated unicode string
// U  -> (int, wchar_t *) -> unicode string with length
// b  -> (int, void *) -> memory with a given size (alias for S)
// B  -> (int *, void *) -> memory with a given size (value at integer)
// i  -> (int) -> integer
// l  -> (long) -> long integer
// L  -> (long *) -> pointer to a long integer
// p  -> (void *) -> pointer (alias for l)
// P  -> (void **) -> pointer to a handle (alias for L)
// o  -> (UNICODE_STRING *) -> unicode string
// O  -> (OBJECT_ATTRIBUTES *) -> wrapper around a unicode string
// a  -> (int, char **) -> array of string
// A  -> (int, wchar_t **) -> array of unicode strings
//
// Each of these format specifiers are prefixed with a zero-terminated key
// value, e.g.
//
// log("s", "key", "value");
//
// A format specifier can also be repeated for n times (with n in the range
// 2..9), e.g.
//
// loq("sss", "key1", "value", "key2", "value2", "key3", "value3");
// loq("3s", "key1", "value", "key2", "value2", "key3", "value3");
//

void loq(const char *fmt, ...);

#define LOQ(fmt, ...) loq("sl" fmt, "function", &__FUNCTION__[4], \
    "return", ret, ##__VA_ARGS__)
