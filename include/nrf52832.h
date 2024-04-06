#pragma once

#include "cpu.h"

#define NRF52832_SRAM_SIZE 0x10000
#define NRF52832_FLASH_SIZE 0x80000

typedef struct NRF52832_inst_t NRF52832_t;

NRF52832_t *nrf52832_new(uint8_t *program, size_t program_size);
void nrf52832_reset(NRF52832_t *nrf52832);
void nrf52832_step(NRF52832_t *nrf52832);

cpu_t *nrf52832_get_cpu(NRF52832_t *nrf52832);
