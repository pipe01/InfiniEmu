#pragma once

#include "nrf52832.h"
#include "components/spi/spinorflash.h"
#include "components/spi/st7789.h"
#include "components/i2c/cst816s.h"
#include "components/i2c/hrs3300.h"

#define PINETIME_EXTFLASH_CS_PIN 5
#define PINETIME_EXTFLASH_SIZE (4 * 1024 * 1024)
#define PINETIME_EXTFLASH_SECTOR_SIZE (4 * 1024)
#define PINETIME_LCD_CS_PIN 25
#define PINETIME_CST816S_IRQ_PIN 28

#define PINETIME_LCD_WIDTH 240
#define PINETIME_LCD_HEIGHT 240

#define PINETIME_CST816S_I2C_ADDR 0x15
#define PINETIME_BMA425_I2C_ADDR 0x18
#define PINETIME_HRS3300_I2C_ADDR 0x44

typedef struct pinetime_t pinetime_t;

pinetime_t *pinetime_new(const uint8_t *program, size_t program_size, bool big_ram, bool big_flash);
void pinetime_free(pinetime_t *);
void pinetime_reset(pinetime_t *);
void pinetime_step(pinetime_t *);

NRF52832_t *pinetime_get_nrf52832(pinetime_t *);
st7789_t *pinetime_get_st7789(pinetime_t *);
cst816s_t *pinetime_get_cst816s(pinetime_t *);
hrs3300_t *pinetime_get_hrs3300(pinetime_t *);
spinorflash_t *pinetime_get_spinorflash(pinetime_t *pt);
