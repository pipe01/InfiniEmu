#pragma once

#include "peripherals/peripheral.h"

PERIPHERAL(SCB, scb)

uint32_t scb_get_prigroup(SCB_t *scb);