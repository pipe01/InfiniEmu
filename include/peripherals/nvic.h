#pragma once

#include "peripherals/peripheral.h"

#include "cpu.h"

PERIPHERAL(NVIC, nvic, cpu_t *cpu, state_store_t *store, size_t priority_bits)