
void pipe_write(const char *fmt, ...);
void pipe_write_read(char *out, int *outlen, const char *fmt, ...);

#define PIPE_MAX_TIMEOUT 10000
#define PIPE_NAME "\\\\.\\pipe\\cuckoo"
