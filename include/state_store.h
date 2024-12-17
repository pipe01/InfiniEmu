#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct state_store_t state_store_t;
typedef uint16_t state_key_t;

#define PERIPHERAL_KEY(id) (0xFF00 | (id))

enum
{
    STATE_KEY_POWER = 1,
    STATE_KEY_CLOCK,

    STATE_KEY_SPIM0 = 0x0100,
    STATE_KEY_TWIM0 = 0x0200,
};

state_store_t *state_store_new();
void state_store_free(state_store_t *);

void state_store_register(state_store_t *store, state_key_t key, void *data, size_t size);
void state_store_freeze(state_store_t *);

uint8_t *state_store_save(state_store_t *, size_t *size);
bool state_store_load(state_store_t *, uint8_t *data, size_t size);
