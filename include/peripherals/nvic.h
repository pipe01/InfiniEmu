#pragma once

#include "peripherals/peripheral.h"

#include "cpu.h"

PERIPHERAL(NVIC, nvic, cpu_t *cpu, size_t priority_bits)