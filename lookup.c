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
#include "lookup.h"

void lookup_init(lookup_t **d)
{
    *d = NULL;
}

void *lookup_add(lookup_t **d, unsigned int id, unsigned int size)
{
    lookup_t *t = (lookup_t *) malloc(sizeof(lookup_t) + size);
    *t = (lookup_t) {
        .next = *d,
        .id   = id,
        .size = size,
    };
    *d = t;
    return t->data;
}

void *lookup_get(lookup_t *d, unsigned int id, unsigned int *size)
{
    for (; d != NULL; d = d->next) {
        if(d->id == id) {
            if(size != NULL) {
                *size = d->size;
            }
            return d->data;
        }
    }
    return NULL;
}

void lookup_del(lookup_t **d, unsigned int id)
{
    // edge case; we want to delete the first entry
    if((*d)->id == id) {
        lookup_t *t = (*d)->next;
        free(*d);
        *d = t;
        return;
    }
    for (lookup_t *t = *d, *last = NULL; t != NULL; last = t, t = t->next) {
        if(t->id == id) {
            if(last != NULL) {
                last->next = t->next;
            }
            free(t);
            break;
        }
    }
}
