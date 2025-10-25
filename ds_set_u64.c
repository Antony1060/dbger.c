#include<stdlib.h>
#include<stdint.h>

#include "ds_set_u64.h"

const float SET_LOAD_FACTOR = 0.6;

static inline uint64_t hash(uint64_t x) {
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}

#define KEY(n) hash(n) % s->capacity;

void ds_set_u64_init_with_capacity(ds_set_u64 *s, size_t capacity) {
    s->size = 0;
    s->capacity = capacity;
    s->table = calloc(s->capacity, sizeof(*s->table));
}

void ds_set_u64_init(ds_set_u64 *s) {
    ds_set_u64_init_with_capacity(s, 4);
}

void ds_set_u64_insert(ds_set_u64 *s, uint64_t item);

static void resize(ds_set_u64 *s) {
    ds_set_u64 new;
    ds_set_u64_init_with_capacity(&new, s->capacity << 1);

    for (size_t i = 0; i < s->capacity; i++) {
        if (!s->table[i]) continue;

        ds_set_u64_insert(&new, s->table[i]);
    }

    free(s->table);

    s->table = new.table;
    s->size = new.size;
    s->capacity = new.capacity;
}

void ds_set_u64_insert(ds_set_u64 *s, uint64_t item) {
    size_t key = KEY(item);

    while(s->table[key] != 0)
        key = (key + 1) & (s->capacity - 1); // power of 2

    s->table[key] = item;
    s->size++;

    if (s->size >= (s->capacity * SET_LOAD_FACTOR)) {
        resize(s);
    }
}

bool ds_set_u64_find(ds_set_u64 *s, uint64_t item) {
    size_t key = KEY(item);

    while (s->table[key] != 0) {
        if (s->table[key] == item)
            return true;

        key = (key + 1) & (s->capacity - 1); // power of 2
    }

    return false;
}

void ds_set_u64_free(ds_set_u64 *s) {
    free(s->table);
}
