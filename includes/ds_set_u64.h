#ifndef __DBGER_SET_U64
#define __DBGER_SET_U64

#include<stdbool.h>

typedef struct {
    size_t size;
    size_t capacity;
    uint64_t *table;
} ds_set_u64;

void ds_set_u64_init(ds_set_u64 *s);

void ds_set_u64_insert(ds_set_u64 *s, uint64_t item);

bool ds_set_u64_find(ds_set_u64 *s, uint64_t item);

void ds_set_u64_clear(ds_set_u64 *s);

void ds_set_u64_free(ds_set_u64 *s);

#endif // __DBGER_SET_U64
