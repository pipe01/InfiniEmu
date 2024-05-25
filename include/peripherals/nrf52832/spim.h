#include "peripherals/peripheral.h"

#include "bus_spi.h"

#define SPIM_ENABLE_VALUE 7

PERIPHERAL(SPIM, spim, uint8_t id, bus_spi_t *spi)
