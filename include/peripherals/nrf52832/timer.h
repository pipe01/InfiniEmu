#pragma once

#include "peripherals/peripheral.h"

#define TIMER_MAX_CC 6

PERIPHERAL(TIMER, timer, uint8_t id, size_t cc_num)
