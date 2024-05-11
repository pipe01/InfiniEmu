#pragma once

#include "bus_spi.h"

spi_slave_t spinorflash_new(size_t size, size_t sector_size, uint8_t csPin);
