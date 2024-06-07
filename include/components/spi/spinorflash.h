#pragma once

#include "bus_spi.h"

#include <stddef.h>

typedef struct spinorflash_t spinorflash_t;

spinorflash_t *spinorflash_new(size_t size, size_t sector_size);
spi_slave_t spinorflash_get_slave(spinorflash_t *);

size_t spinorflash_get_write_count(spinorflash_t *);
void spinorflash_read(spinorflash_t *, size_t offset, uint8_t *data, size_t data_size);
void spinorflash_write(spinorflash_t *, size_t offset, const uint8_t *data, size_t data_size);
