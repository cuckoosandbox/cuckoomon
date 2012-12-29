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
