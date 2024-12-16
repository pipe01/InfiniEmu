#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct state_store_t state_store_t;
typedef uint16_t state_key_t;

#define PERIPHERAL_KEY(id) (0xFF00 | (id))

state_store_t *state_store_new();
void state_store_free(state_store_t *);

void *state_store_alloc(state_store_t *, state_key_t key, size_t size);
void state_store_freeze(state_store_t *);

uint8_t *state_store_save(state_store_t *, size_t *size);
bool state_store_load(state_store_t *, uint8_t *data, size_t size);
