#pragma once

#include "peripherals/peripheral.h"
#include "cpu.h"

PERIPHERAL(SCB, scb, cpu_t *cpu)

uint32_t scb_get_prigroup(SCB_t *scb);
