
typedef struct _dict_t {
    unsigned int id;
    unsigned int size;
    void *data;
} dict_t;

void dict_init(dict_t **d, unsigned int *count);
void *dict_add(dict_t **d, unsigned int *count, unsigned int id,
    unsigned int size);
void *dict_get(dict_t *d, unsigned int count, unsigned int id,
    unsigned int *size);
void dict_del(dict_t **d, unsigned int *count, unsigned int id);
