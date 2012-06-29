
typedef struct _hook_t {
    const char *library;
    const char *funcname;

    // instead of a library/funcname combination, an address can be given
    // as well
    void *addr;

    // pointer to the new function
    void *new_func;

    // "function" which jumps over the trampoline and executes the original
    // function call
    void **old_func;

    unsigned char gate[64];
} hook_t;

int lde(void *addr);

int hook_create_callgate(unsigned char *addr, int len, unsigned char *gate);

int hook_api(hook_t *h, int type);

#define HOOK_DIRECT_JMP 0
