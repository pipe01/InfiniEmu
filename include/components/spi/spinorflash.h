#pragma once

#include "bus_spi.h"
#include "state_store.h"

#include <stddef.h>

typedef struct spinorflash_t spinorflash_t;

spinorflash_t *spinorflash_new(state_store_t *store, size_t size, size_t sector_size);
spi_slave_t spinorflash_get_slave(spinorflash_t *);

size_t spinorflash_get_write_count(spinorflash_t *);
void spinorflash_set_buffer(spinorflash_t *, uint8_t *data);
uint8_t *spinorflash_get_buffer(spinorflash_t *);
size_t spinorflash_get_buffer_size(spinorflash_t *);
