
typedef struct _hook_t {
    const char *library;
    const char *funcname;

    // instead of a library/funcname combination, an address can be given
    // as well (this address has more priority than library/funcname)
    void *addr;

    // pointer to the new function
    void *new_func;

    // "function" which jumps over the trampoline and executes the original
    // function call
    void **old_func;

    // max hooking depth (see comments @ hook_create_pre_gate)
    int max_depth;

    unsigned char gate[64];
    unsigned char pre_gate[64];
} hook_t;

int lde(void *addr);

int hook_create_callgate(unsigned char *addr, int len, unsigned char *gate);

int hook_api(hook_t *h, int type);

void hook_enable();
void hook_disable();

#define HOOK_DIRECT_JMP 0
#define HOOK_NOP_DIRECT_JMP 1

#define HOOKDEF(return_value, calling_convention, apiname, ...) \
    return_value (calling_convention *Old_##apiname)(__VA_ARGS__); \
    return_value calling_convention New_##apiname(__VA_ARGS__)
