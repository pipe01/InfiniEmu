#pragma once

#include "peripherals/peripheral.h"

#define DWT_CYCCNTENA 0

PERIPHERAL(DWT, dwt)

void dwt_increment_cycle(DWT_t *dwt, unsigned int count);
