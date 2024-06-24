#pragma once

#include "cpu.h"
#include "bus_i2c.h"
#include "bus_spi.h"
#include "program.h"
#include "peripherals/nrf52832/rtc.h"

#define NRF52832_SRAM_SIZE 0x10000
#define NRF52832_FLASH_SIZE 0x80000

#define NRF52832_PRIORITY_BITS 3

#define NRF52832_MAX_EXTERNAL_INTERRUPTS 496

enum
{
    INSTANCE_CLOCK = 0x00,
    INSTANCE_POWER = 0x00,
    INSTANCE_BPROT = 0x00,
    INSTANCE_RADIO = 0x01,
    INSTANCE_UARTE0 = 0x02,
    INSTANCE_UART0 = 0x02,
    INSTANCE_SPIM0 = 0x03,
    INSTANCE_SPIS0 = 0x03,
    INSTANCE_TWIM0 = 0x03,
    INSTANCE_TWI0 = 0x03,
    INSTANCE_SPI0 = 0x03,
    INSTANCE_TWIS0 = 0x03,
    INSTANCE_SPIM1 = 0x04,
    INSTANCE_TWI1 = 0x04,
    INSTANCE_SPIS1 = 0x04,
    INSTANCE_TWIS1 = 0x04,
    INSTANCE_TWIM1 = 0x04,
    INSTANCE_SPI1 = 0x04,
    INSTANCE_NFCT = 0x05,
    INSTANCE_GPIOTE = 0x06,
    INSTANCE_SAADC = 0x07,
    INSTANCE_TIMER0 = 0x08,
    INSTANCE_TIMER1 = 0x09,
    INSTANCE_TIMER2 = 0x0A,
    INSTANCE_RTC0 = 0x0B,
    INSTANCE_TEMP = 0x0C,
    INSTANCE_RNG = 0x0D,
    INSTANCE_ECB = 0x0E,
    INSTANCE_CCM = 0x0F,
    INSTANCE_AAR = 0x0F,
    INSTANCE_WDT = 0x10,
    INSTANCE_RTC1 = 0x11,
    INSTANCE_QDEC = 0x12,
    INSTANCE_LPCOMP = 0x13,
    INSTANCE_COMP = 0x13,
    INSTANCE_SWI0 = 0x14,
    INSTANCE_EGU0 = 0x14,
    INSTANCE_EGU1 = 0x15,
    INSTANCE_SWI1 = 0x15,
    INSTANCE_SWI2 = 0x16,
    INSTANCE_EGU2 = 0x16,
    INSTANCE_SWI3 = 0x17,
    INSTANCE_EGU3 = 0x17,
    INSTANCE_EGU4 = 0x18,
    INSTANCE_SWI4 = 0x18,
    INSTANCE_SWI5 = 0x19,
    INSTANCE_EGU5 = 0x19,
    INSTANCE_TIMER3 = 0x1A,
    INSTANCE_TIMER4 = 0x1B,
    INSTANCE_PWM0 = 0x1C,
    INSTANCE_PDM = 0x1D,
    INSTANCE_NVMC = 0x1E,
    INSTANCE_PPI = 0x1F,
    INSTANCE_MWU = 0x20,
    INSTANCE_PWM1 = 0x21,
    INSTANCE_PWM2 = 0x22,
    INSTANCE_SPI2 = 0x23,
    INSTANCE_SPIS2 = 0x23,
    INSTANCE_SPIM2 = 0x23,
    INSTANCE_RTC2 = 0x24,
    INSTANCE_I2S = 0x25,
    INSTANCE_FPU = 0x26,
};

typedef struct NRF52832_inst_t NRF52832_t;

NRF52832_t *nrf52832_new(const program_t *flash, size_t sram_size);
void nrf52832_reset(NRF52832_t *);
void nrf52832_step(NRF52832_t *);

cpu_t *nrf52832_get_cpu(NRF52832_t *);
bus_spi_t *nrf52832_get_spi(NRF52832_t *);
bus_i2c_t *nrf52832_get_i2c(NRF52832_t *);
pins_t *nrf52832_get_pins(NRF52832_t *);
void *nrf52832_get_peripheral(NRF52832_t *, uint8_t instance_id);

double nrf52832_get_used_sram(NRF52832_t *);
