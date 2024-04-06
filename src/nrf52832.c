#define _POSIX_C_SOURCE 2

#include <string.h>

#include "nrf52832.h"
#include "byte_util.h"

#include "peripherals/nrf52832/clock.h"
#include "peripherals/nrf52832/comp.h"
#include "peripherals/nrf52832/power.h"
#include "peripherals/nrf52832/radio.h"
#include "peripherals/nrf52832/temp.h"
#include "peripherals/ppb_scb.h"

#include "../dumps/ficr.h"
#include "../dumps/uicr.h"
#include "../dumps/secret.h"

struct NRF52832_inst_t {
    cpu_t *cpu;

    CLOCK_t *clock;
    COMP_t *comp;
    POWER_t *power;
    RADIO_t *radio;
    TEMP_t *temp;
    SCB_t *scb;
};

#define NEW_PERIPH(type, name, addr, size, ...) \
    chip->name = name##_new(__VA_ARGS__); \
    name##_reset(chip->name); \
    last = last->next = memreg_new_operation(addr, size, name##_operation, chip->name);

NRF52832_t *nrf52832_new(uint8_t *program, size_t program_size)
{
    NRF52832_t *chip = (NRF52832_t *)malloc(sizeof(NRF52832_t));

    uint8_t *flash = malloc(NRF52832_FLASH_SIZE);
    memcpy(flash, program, program_size);
    memset(flash + program_size, 0xFF, NRF52832_FLASH_SIZE - program_size); // 0xFF out the rest of the flash

    uint8_t *sram = malloc(NRF52832_SRAM_SIZE);

    memreg_t *mem_first = memreg_new_simple(0, flash, NRF52832_FLASH_SIZE);
    memreg_t *last = mem_first;

    last = last->next = memreg_new_simple(x(2000, 0000), sram, NRF52832_SRAM_SIZE);

    NEW_PERIPH(COMP, comp, x(4001, 3000), 0x1000);
    NEW_PERIPH(CLOCK, clock, x(4000, 0000), 0x1000);
    NEW_PERIPH(POWER, power, x(4000, 0000), 0x1000);
    NEW_PERIPH(RADIO, radio, x(4000, 1000), 0x1000);
    NEW_PERIPH(TEMP, temp, x(4000, C000), 0x1000);

    last = last->next = memreg_new_simple_copy(x(F000, 0000), dumps_secret_bin, dumps_secret_bin_len);
    last = last->next = memreg_new_simple_copy(x(1000, 0000), dumps_ficr_bin, dumps_ficr_bin_len);
    last = last->next = memreg_new_simple_copy(x(1000, 1000), dumps_uicr_bin, dumps_uicr_bin_len);

    NEW_PERIPH(SCB, scb, x(E000, ED00), 0x8F);

    chip->cpu = cpu_new(flash, NRF52832_FLASH_SIZE, mem_first);

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
