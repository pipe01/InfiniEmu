#pragma once

#include "peripherals/peripheral.h"

#define TIMER_MAX_CC 6

NRF52_PERIPHERAL(TIMER, timer, size_t cc_num)
