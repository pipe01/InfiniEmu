#include "state_store.h"

#include <stdlib.h>
#include <string.h>

typedef struct
{
    uint16_t key;
    size_t size;
} entry_header_t;

typedef struct
{
    entry_header_t header;
    void *data;
} entry_t;

#define MAX_ENTRIES 100

struct state_store_t
{
    entry_t entries[MAX_ENTRIES];
    size_t entries_count;

    bool frozen;
};

state_store_t *state_store_new()
{
    state_store_t *store = malloc(sizeof(state_store_t));
    store->entries_count = 0;
    store->frozen = false;

    return store;
}

void state_store_free(state_store_t *store)
{
    for (size_t i = 0; i < store->entries_count; i++)
        free(store->entries[i].data);

    free(store);
}

static entry_t *find_entry(state_store_t *store, state_key_t key)
{
    for (size_t i = 0; i < store->entries_count; i++)
        if (store->entries[i].header.key == key)
            return &store->entries[i];

    return NULL;
}

void state_store_register(state_store_t *store, state_key_t key, void *data, size_t size)
{
    if (store->frozen)
        abort();

    if (find_entry(store, key))
        abort();

    store->entries[store->entries_count++] = (entry_t){
        .header.key = key,
        .header.size = size,
        .data = data,
    };
}

void state_store_freeze(state_store_t *store)
{
    store->frozen = true;
}

uint8_t *state_store_save(state_store_t *store, size_t *size)
{
    *size = 0;

    for (size_t i = 0; i < store->entries_count; i++)
        *size += sizeof(entry_header_t) + store->entries[i].header.size;

    uint8_t *data = malloc(*size);

    size_t offset = 0;
    for (size_t i = 0; i < store->entries_count; i++)
    {
        memcpy(data + offset, &store->entries[i].header, sizeof(entry_header_t));
        offset += sizeof(entry_header_t);

        memcpy(data + offset, store->entries[i].data, store->entries[i].header.size);
        offset += store->entries[i].header.size;
    }

    return data;
}

bool state_store_load(state_store_t *store, uint8_t *data, size_t size)
{
    entry_header_t header;

    size_t offset = 0;
    while (offset < size)
    {
        memcpy(&header, data + offset, sizeof(entry_header_t));
        offset += sizeof(entry_header_t);

        entry_t *entry = find_entry(store, header.key);
        if (!entry || entry->header.size != header.size) {
            return false;
        }

        memcpy(entry->data, data + offset, header.size);
        offset += header.size;
    }

    return true;
}
