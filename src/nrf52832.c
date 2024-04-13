#define _POSIX_C_SOURCE 2

#include <string.h>

#include "nrf52832.h"
#include "byte_util.h"

#include "peripherals/peripheral.h"
#include "peripherals/nrf52832/clock.h"
#include "peripherals/nrf52832/comp.h"
#include "peripherals/nrf52832/gpio.h"
#include "peripherals/nrf52832/power.h"
#include "peripherals/nrf52832/radio.h"
#include "peripherals/nrf52832/temp.h"
#include "peripherals/nrf52832/timer.h"

#include "../dumps/ficr.h"
#include "../dumps/uicr.h"
#include "../dumps/secret.h"

struct NRF52832_inst_t
{
    cpu_t *cpu;

    CLOCK_t *clock;
    COMP_t *comp;
    POWER_t *power;
    RADIO_t *radio;
    TEMP_t *temp;
    GPIO_t *gpio;
    TIMER_t *timer0, *timer1, *timer2, *timer3, *timer4;
};

NRF52832_t *nrf52832_new(uint8_t *program, size_t program_size)
{
    NRF52832_t *chip = (NRF52832_t *)malloc(sizeof(NRF52832_t));

    uint8_t *flash = malloc(NRF52832_FLASH_SIZE);
    memcpy(flash, program, program_size);
    memset(flash + program_size, 0xFF, NRF52832_FLASH_SIZE - program_size); // 0xFF out the rest of the flash

    uint8_t *sram = malloc(NRF52832_SRAM_SIZE);

    memreg_t *mem_first = memreg_new_simple(0, flash, NRF52832_FLASH_SIZE);
    memreg_t *last = mem_first;

    last = memreg_set_next(last, memreg_new_simple(x(2000, 0000), sram, NRF52832_SRAM_SIZE));

    NEW_PERIPH(chip, COMP, comp, comp, x(4001, 3000), 0x1000);
    NEW_PERIPH(chip, CLOCK, clock, clock, x(4000, 0000), 0x1000);
    NEW_PERIPH(chip, POWER, power, power, x(4000, 0000), 0x1000);
    NEW_PERIPH(chip, RADIO, radio, radio, x(4000, 1000), 0x1000);
    NEW_PERIPH(chip, TIMER, timer, timer0, x(4000, 8000), 0x1000, 4);
    NEW_PERIPH(chip, TIMER, timer, timer1, x(4000, 9000), 0x1000, 4);
    NEW_PERIPH(chip, TIMER, timer, timer2, x(4000, A000), 0x1000, 4);
    NEW_PERIPH(chip, TEMP, temp, temp, x(4000, C000), 0x1000);
    NEW_PERIPH(chip, TIMER, timer, timer3, x(4001, A000), 0x1000, 6);
    NEW_PERIPH(chip, TIMER, timer, timer4, x(4001, B000), 0x1000, 6);
    NEW_PERIPH(chip, GPIO, gpio, gpio, x(5000, 0000), 0x1000);

    last = memreg_set_next(last, memreg_new_simple_copy(x(F000, 0000), dumps_secret_bin, dumps_secret_bin_len));
    last = memreg_set_next(last, memreg_new_simple_copy(x(1000, 0000), dumps_ficr_bin, dumps_ficr_bin_len));
    last = memreg_set_next(last, memreg_new_simple_copy(x(1000, 1000), dumps_uicr_bin, dumps_uicr_bin_len));

    chip->cpu = cpu_new(flash, NRF52832_FLASH_SIZE, mem_first, NRF52832_MAX_EXTERNAL_INTERRUPTS);

    cpu_reset(chip->cpu);

    return chip;
}

void nrf52832_reset(NRF52832_t *nrf52832)
{
    cpu_reset(nrf52832->cpu);
}

void nrf52832_step(NRF52832_t *nrf52832)
{
    cpu_step(nrf52832->cpu);
}

cpu_t *nrf52832_get_cpu(NRF52832_t *nrf52832)
{
    return nrf52832->cpu;
}
