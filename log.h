
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
// i  -> (int) -> integer
// l  -> (long) -> long integer
// p  -> (void *) -> pointer (alias for l)
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
