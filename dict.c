#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dict.h"

// rounds v up to the next highest power of 2
// http://www-graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
static unsigned int roundup2(unsigned int v)
{
    v--, v |= v >> 1, v |= v >> 2, v |= v >> 4;
    return v |= v >> 8, v |= v >> 16, ++v;
}

void dict_init(dict_t **d, unsigned int *count)
{
    *d = NULL;
    *count = 0;
}

void *dict_add(dict_t **d, unsigned int *count, unsigned int id,
    unsigned int size)
{
    unsigned int new_count = roundup2(*count + 1);
    if(new_count != roundup2(*count)) {
        *d = (dict_t *) realloc(*d, new_count * sizeof(dict_t));
    }

    // null-pointer error checking is overrated
    dict_t *t = &(*d)[*count];
    t->id = id, t->size = size;
    t->data = malloc(size);
    return *count += 1, t->data;
}

void *dict_get(dict_t *d, unsigned int count, unsigned int id,
    unsigned int *size)
{
    while (count-- != 0) {
        if(d->id == id) {
            *size = d->size;
            return d->data;
        }
    }
    return NULL;
}

void dict_del(dict_t **d, unsigned int *count, unsigned int id)
{
    dict_t *t = *d;
    for (unsigned int i = 0; i < *count; i++) {
        if(t->id == id) {
            free(t->data);
            memcpy(t, t + 1, *count - i - 1);
            *count -= 1;
            return;
        }
    }
}
