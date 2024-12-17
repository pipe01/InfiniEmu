#pragma once

#include "peripherals/peripheral.h"

#define DWT_CYCCNTENA 0

PERIPHERAL(DWT, dwt, state_store_t *store)

void dwt_increment_cycle(DWT_t *dwt, unsigned int count);
