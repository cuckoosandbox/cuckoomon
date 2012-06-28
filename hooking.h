
typedef struct _hook_t {
    const char *library;
    const char *funcname;

    // pointer to the new function
    void *new_func;

    // "function" which jumps over the trampoline and executes the original
    // function call
    void **old_func;
} hook_t;

int lde(void *addr);

int hook_api(hook_t *h);
