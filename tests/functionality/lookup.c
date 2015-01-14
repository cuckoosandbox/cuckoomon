/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

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
#include "lookup.h"

typedef struct _entry_t {
    struct _entry_t *next;
    unsigned int id;
    unsigned int size;
    unsigned char data[0];
} entry_t;

int main(void)
{
    lookup_t a;

    lookup_init(&a);
    strcpy((char *) lookup_add(&a, 1, 10), "abc");
    strcpy((char *) lookup_add(&a, 2, 20), "def");
    lookup_del(&a, 1);
    strcpy((char *) lookup_add(&a, 3, 30), "ghi");
    strcpy((char *) lookup_add(&a, 4, 40), "jkl");
    lookup_del(&a, 4);

    for (int i = 0; i < 5; i++) {
        printf("%d -> %p\n", i, lookup_get(&a, i, NULL));
    }

    for (entry_t *p = a.root; p != NULL; p = p->next) {
        printf("%p %d %d\n", p, p->id, p->size);
    }

	return 0;
}
