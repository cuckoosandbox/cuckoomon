/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2013 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
