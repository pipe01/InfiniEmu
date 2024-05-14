#define _POSIX_C_SOURCE 2

#include <string.h>

#include "byte_util.h"
#include "bus_i2c.h"
#include "bus_spi.h"
#include "nrf52832.h"
#include "pins.h"

#include "components/spi/spinorflash.h"

#include "peripherals/peripheral.h"
#include "peripherals/nrf52832/clock.h"
#include "peripherals/nrf52832/comp.h"
#include "peripherals/nrf52832/gpio.h"
#include "peripherals/nrf52832/gpiote.h"
#include "peripherals/nrf52832/power.h"
#include "peripherals/nrf52832/ppi.h"
#include "peripherals/nrf52832/rtc.h"
#include "peripherals/nrf52832/radio.h"
#include "peripherals/nrf52832/saadc.h"
#include "peripherals/nrf52832/spim.h"
#include "peripherals/nrf52832/temp.h"
#include "peripherals/nrf52832/timer.h"
#include "peripherals/nrf52832/twim.h"
#include "peripherals/nrf52832/wdt.h"

#include "../dumps/ficr.h"
#include "../dumps/uicr.h"
#include "../dumps/secret.h"

struct NRF52832_inst_t
{
    cpu_t *cpu;

    uint64_t cycle_counter;

    memreg_t *mem;
    bus_spi_t *spi;
    bus_i2c_t *i2c;
    pins_t *pins;

    CLOCK_t *clock;
    COMP_t *comp;
    POWER_t *power;
    RADIO_t *radio;
    TEMP_t *temp;
    GPIO_t *gpio;
    GPIOTE_t *gpiote;
    RTC_t *rtc[3];
    TIMER_t *timer[5];
    WDT_t *wdt;
    SPIM_t *spim[3];
    PPI_t *ppi;
    TWIM_t *twim[2];
    SAADC_t *saadc;
};

NRF52832_t *nrf52832_new(const uint8_t *program, size_t program_size, size_t sram_size)
{
    uint8_t *sram = malloc(sram_size);

    NRF52832_t *chip = (NRF52832_t *)malloc(sizeof(NRF52832_t));
    chip->pins = pins_new();
    chip->spi = spi_new(chip->pins, sram, sram_size);
    chip->i2c = i2c_new(sram, sram_size);

    uint8_t *flash = malloc(NRF52832_FLASH_SIZE);
    memcpy(flash, program, program_size);
    memset(flash + program_size, 0xFF, NRF52832_FLASH_SIZE - program_size); // 0xFF out the rest of the flash

    chip->mem = memreg_new_simple(0, flash, NRF52832_FLASH_SIZE);
    memreg_t *last = chip->mem;

    last = memreg_set_next(last, memreg_new_simple(x(2000, 0000), sram, sram_size));

    NEW_PERIPH(chip, CLOCK, clock, clock, x(4000, 0000), 0x1000);
    NEW_PERIPH(chip, POWER, power, power, x(4000, 0000), 0x1000);
    NEW_PERIPH(chip, RADIO, radio, radio, x(4000, 1000), 0x1000);
    NEW_PERIPH(chip, SPIM, spim, spim[0], x(4000, 3000), 0x1000, chip->spi);
    NEW_PERIPH(chip, TWIM, twim, twim[0], x(4000, 3000), 0x1000, chip->i2c);
    NEW_PERIPH(chip, SPIM, spim, spim[1], x(4000, 4000), 0x1000, chip->spi);
    NEW_PERIPH(chip, TWIM, twim, twim[1], x(4000, 4000), 0x1000, chip->i2c);
    NEW_PERIPH(chip, GPIOTE, gpiote, gpiote, x(4000, 6000), 0x1000);
    NEW_PERIPH(chip, SAADC, saadc, saadc, x(4000, 7000), 0x1000, chip->pins);
    NEW_PERIPH(chip, TIMER, timer, timer[0], x(4000, 8000), 0x1000, 4);
    NEW_PERIPH(chip, TIMER, timer, timer[1], x(4000, 9000), 0x1000, 4);
    NEW_PERIPH(chip, TIMER, timer, timer[2], x(4000, A000), 0x1000, 4);
    NEW_PERIPH(chip, RTC, rtc, rtc[0], x(4000, B000), 0x1000, 3, &chip->cpu, 0x0B);
    NEW_PERIPH(chip, TEMP, temp, temp, x(4000, C000), 0x1000);
    NEW_PERIPH(chip, WDT, wdt, wdt, x(4001, 0000), 0x1000);
    NEW_PERIPH(chip, RTC, rtc, rtc[1], x(4001, 1000), 0x1000, 4, &chip->cpu, 0x11);
    NEW_PERIPH(chip, COMP, comp, comp, x(4001, 3000), 0x1000);
    NEW_PERIPH(chip, TIMER, timer, timer[3], x(4001, A000), 0x1000, 6);
    NEW_PERIPH(chip, TIMER, timer, timer[4], x(4001, B000), 0x1000, 6);
    NEW_PERIPH(chip, PPI, ppi, ppi, x(4001, F000), 0x1000);
    NEW_PERIPH(chip, SPIM, spim, spim[2], x(4002, 3000), 0x1000, chip->spi);
    NEW_PERIPH(chip, RTC, rtc, rtc[2], x(4002, 4000), 0x1000, 4, &chip->cpu, 0x24);
    NEW_PERIPH(chip, GPIO, gpio, gpio, x(5000, 0000), 0x1000, chip->pins);

    last = memreg_set_next(last, memreg_new_simple_copy(x(F000, 0000), dumps_secret_bin, dumps_secret_bin_len));
    last = memreg_set_next(last, memreg_new_simple_copy(x(1000, 0000), dumps_ficr_bin, dumps_ficr_bin_len));
    last = memreg_set_next(last, memreg_new_simple_copy(x(1000, 1000), dumps_uicr_bin, dumps_uicr_bin_len));

    chip->cpu = cpu_new(flash, NRF52832_FLASH_SIZE, chip->mem, NRF52832_MAX_EXTERNAL_INTERRUPTS, NRF52832_PRIORITY_BITS);

    return chip;
}

void nrf52832_reset(NRF52832_t *nrf52832)
{
    nrf52832->cycle_counter = 0;

    memreg_reset_all(nrf52832->mem);
    pins_reset(nrf52832->pins);
    spi_reset(nrf52832->spi);
    i2c_reset(nrf52832->i2c);
    cpu_reset(nrf52832->cpu);
}

void nrf52832_step(NRF52832_t *nrf52832)
{
    // TODO: Properly measure time
    if ((++nrf52832->cycle_counter % 50) == 0)
    {
        rtc_tick(nrf52832->rtc[0]);
        rtc_tick(nrf52832->rtc[1]);
        rtc_tick(nrf52832->rtc[2]);
    }

    spi_step(nrf52832->spi);

    cpu_step(nrf52832->cpu);
}

cpu_t *nrf52832_get_cpu(NRF52832_t *chip)
{
    return chip->cpu;
}

bus_spi_t *nrf52832_get_spi(NRF52832_t *chip)
{
    return chip->spi;
}

bus_i2c_t *nrf52832_get_i2c(NRF52832_t *chip)
{
    return chip->i2c;
}
