#pragma once

#include "nrf52832.h"

#define PINETIME_EXTFLASH_CS_PIN 5
#define PINETIME_EXTFLASH_SIZE (4 * 1024 * 1024)
#define PINETIME_EXTFLASH_SECTOR_SIZE (4 * 1024)

#define PINETIME_CST816S_I2C_ADDR 0x15
#define PINETIME_BMA425_I2C_ADDR 0x18
#define PINETIME_HRS3300_I2C_ADDR 0x44

typedef struct pinetime_t pinetime_t;

pinetime_t *pinetime_new(const uint8_t *program, size_t program_size);
void pinetime_free(pinetime_t *);
void pinetime_reset(pinetime_t *);
void pinetime_step(pinetime_t *);

NRF52832_t *pinetime_get_nrf52832(pinetime_t *);
