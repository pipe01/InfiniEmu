#pragma once

#include "peripherals/peripheral.h"
#include "bus_i2c.h"

#define TWIM_ENABLE_VALUE 6

PERIPHERAL(TWIM, twim, uint8_t id, bus_i2c_t *i2c)
