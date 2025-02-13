#include <string.h>

#include "byte_util.h"
#include "bus_i2c.h"
#include "bus_spi.h"
#include "nrf52832.h"
#include "pins.h"
#include "ticker.h"

#include "components/spi/spinorflash.h"

#include "peripherals/peripheral.h"
#include "peripherals/nrf52832/ccm.h"
#include "peripherals/nrf52832/clock.h"
#include "peripherals/nrf52832/comp.h"
#include "peripherals/nrf52832/ecb.h"
#include "peripherals/nrf52832/gpio.h"
#include "peripherals/nrf52832/gpiote.h"
#include "peripherals/nrf52832/nvmc.h"
#include "peripherals/nrf52832/power.h"
#include "peripherals/nrf52832/ppi.h"
#include "peripherals/nrf52832/pwm.h"
#include "peripherals/nrf52832/rng.h"
#include "peripherals/nrf52832/rtc.h"
#include "peripherals/nrf52832/radio.h"
#include "peripherals/nrf52832/saadc.h"
#include "peripherals/nrf52832/spi.h"
#include "peripherals/nrf52832/spim.h"
#include "peripherals/nrf52832/temp.h"
#include "peripherals/nrf52832/timer.h"
#include "peripherals/nrf52832/twim.h"
#include "peripherals/nrf52832/wdt.h"

#include "../dumps/ficr.h"
#include "../dumps/uicr.h"
#include "../dumps/secret.h"

#define SRAM_FILL_BYTE 0xB5

struct NRF52832_inst_t
{
    cpu_t *cpu;
    state_store_t *state_store;

    uint8_t *flash;
    size_t flash_size;

    uint8_t *sram;
    size_t sram_size;

    uint64_t cycle_counter;

    memory_map_t *mem;
    bus_spi_t *bus_spi;
    bus_i2c_t *bus_i2c;
    pins_t *pins;
    ticker_t *ticker;
    dma_t *dma;

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
    RNG_t *rng;
    CCM_t *ccm;
    ECB_t *ecb;
    NVMC_t *nvmc;
    SPI_t *spi[3];
    PWM_t *pwm[3];
};

#define NEW_NRF52_PERIPH(chip, type, name, field, idn, ...)                                                                                     \
    do                                                                                                                                          \
    {                                                                                                                                           \
        ctx.id = idn;                                                                                                                           \
        (chip)->field = name##_new(ctx, ##__VA_ARGS__);                                                                                         \
        memory_map_add_region((chip)->mem, memreg_new_operation(0x40000000 | (((idn) & 0xFF) << 12), 0x1000, name##_operation, (chip)->field)); \
    } while (0)

NRF52832_t *nrf52832_new(const program_t *flash, size_t sram_size, state_store_t *store)
{
    uint8_t *sram = malloc(sram_size);
    memset(sram, SRAM_FILL_BYTE, sram_size);

    NRF52832_t *chip = malloc(sizeof(NRF52832_t));
    chip->state_store = store;
    chip->sram = sram;
    chip->sram_size = sram_size;
    chip->pins = pins_new(store, 3300, 2310);
    chip->bus_spi = bus_spi_new(chip->pins, sram, sram_size, store);
    chip->bus_i2c = i2c_new(sram, sram_size);
    chip->ticker = ticker_new(NRF52832_HFCLK_FREQUENCY / NRF52832_LFCLK_FREQUENCY);
    chip->dma = dma_new(ARM_SRAM_START, sram, sram_size);

    state_store_register(store, STATE_KEY_MEMORY, sram, sram_size);

    chip->flash_size = program_size(flash);
    chip->flash = malloc(chip->flash_size);
    program_write_to(flash, chip->flash, chip->flash_size);

    chip->mem = memory_map_new();

    memory_map_add_region(chip->mem, memreg_new_simple(x(2000, 0000), sram, sram_size));

    // PPI must be created first to allow for other peripherals to subscribe to it
    NEW_PERIPH(chip, PPI, ppi, ppi, x(4001, F000), 0x1000, &chip->cpu);
    current_ppi = chip->ppi;

    nrf52_peripheral_context_t ctx = {
        .cpu = &chip->cpu,
        .pins = chip->pins,
        .ppi = chip->ppi,
        .ticker = chip->ticker,
        .i2c = chip->bus_i2c,
        .spi = chip->bus_spi,
        .dma = chip->dma,
        .state_store = store,
    };

    NEW_NRF52_PERIPH(chip, NVMC, nvmc, nvmc, INSTANCE_NVMC, chip->flash, program_size(flash));
    memory_map_add_region(chip->mem, memreg_new_operation(0, program_size(flash), nvmc_operation, chip->nvmc));

    NEW_NRF52_PERIPH(chip, CLOCK, clock, clock, INSTANCE_CLOCK);
    NEW_NRF52_PERIPH(chip, POWER, power, power, INSTANCE_POWER);
    NEW_NRF52_PERIPH(chip, RADIO, radio, radio, INSTANCE_RADIO);
    NEW_NRF52_PERIPH(chip, GPIOTE, gpiote, gpiote, INSTANCE_GPIOTE);
    NEW_NRF52_PERIPH(chip, SAADC, saadc, saadc, INSTANCE_SAADC);
    NEW_NRF52_PERIPH(chip, TEMP, temp, temp, INSTANCE_TEMP);
    NEW_NRF52_PERIPH(chip, RNG, rng, rng, INSTANCE_RNG);
    NEW_NRF52_PERIPH(chip, ECB, ecb, ecb, INSTANCE_ECB);
    NEW_NRF52_PERIPH(chip, CCM, ccm, ccm, INSTANCE_CCM);
    NEW_NRF52_PERIPH(chip, WDT, wdt, wdt, INSTANCE_WDT);
    NEW_NRF52_PERIPH(chip, COMP, comp, comp, INSTANCE_COMP);
    NEW_NRF52_PERIPH(chip, RTC, rtc, rtc[0], INSTANCE_RTC0, 3);
    NEW_NRF52_PERIPH(chip, RTC, rtc, rtc[1], INSTANCE_RTC1, 4);
    NEW_NRF52_PERIPH(chip, RTC, rtc, rtc[2], INSTANCE_RTC2, 4);
    NEW_NRF52_PERIPH(chip, SPI, spi, spi[0], INSTANCE_SPI0);
    NEW_NRF52_PERIPH(chip, SPI, spi, spi[1], INSTANCE_SPI1);
    NEW_NRF52_PERIPH(chip, SPI, spi, spi[2], INSTANCE_SPI2);
    NEW_NRF52_PERIPH(chip, SPIM, spim, spim[0], INSTANCE_SPIM0);
    NEW_NRF52_PERIPH(chip, SPIM, spim, spim[1], INSTANCE_SPIM1);
    NEW_NRF52_PERIPH(chip, SPIM, spim, spim[2], INSTANCE_SPIM2);
    NEW_NRF52_PERIPH(chip, TWIM, twim, twim[0], INSTANCE_TWIM0);
    NEW_NRF52_PERIPH(chip, TWIM, twim, twim[1], INSTANCE_TWIM1);
    NEW_NRF52_PERIPH(chip, TIMER, timer, timer[0], INSTANCE_TIMER0, 4);
    NEW_NRF52_PERIPH(chip, TIMER, timer, timer[1], INSTANCE_TIMER1, 4);
    NEW_NRF52_PERIPH(chip, TIMER, timer, timer[2], INSTANCE_TIMER2, 4);
    NEW_NRF52_PERIPH(chip, TIMER, timer, timer[3], INSTANCE_TIMER3, 6);
    NEW_NRF52_PERIPH(chip, TIMER, timer, timer[4], INSTANCE_TIMER4, 6);
    NEW_NRF52_PERIPH(chip, PWM, pwm, pwm[0], INSTANCE_PWM0);
    NEW_NRF52_PERIPH(chip, PWM, pwm, pwm[1], INSTANCE_PWM1);
    NEW_NRF52_PERIPH(chip, PWM, pwm, pwm[2], INSTANCE_PWM2);
    NEW_PERIPH(chip, GPIO, gpio, gpio, x(5000, 0000), 0x1000, ctx);

    memory_map_add_region(chip->mem, memreg_new_simple_copy(x(F000, 0000), dumps_secret_bin, dumps_secret_bin_len));
    memory_map_add_region(chip->mem, memreg_new_simple_copy(x(1000, 0000), dumps_ficr_bin, dumps_ficr_bin_len));
    memory_map_add_region(chip->mem, memreg_new_simple_copy(x(1000, 1000), dumps_uicr_bin, dumps_uicr_bin_len));

    chip->cpu = cpu_new(chip->flash, program_size(flash), chip->mem, store, NRF52832_MAX_EXTERNAL_INTERRUPTS, NRF52832_PRIORITY_BITS);

    return chip;
}

void nrf52832_free(NRF52832_t *nrf)
{
    cpu_free(nrf->cpu);
    free(nrf->sram);
    pins_free(nrf->pins);
    bus_spi_free(nrf->bus_spi);
    i2c_free(nrf->bus_i2c);
    ticker_free(nrf->ticker);
    dma_free(nrf->dma);
    free(nrf->flash);
    // memory_map_free(nrf->mem);

    free(nrf);
}

void nrf52832_reset(NRF52832_t *nrf52832)
{
    nrf52832->cycle_counter = 0;

    memory_map_do_operation_all(nrf52832->mem, OP_RESET);
    pins_reset(nrf52832->pins);
    bus_spi_reset(nrf52832->bus_spi);
    i2c_reset(nrf52832->bus_i2c);
    ticker_reset(nrf52832->ticker);
    cpu_reset(nrf52832->cpu);
}

int nrf52832_step(NRF52832_t *nrf52832)
{
    current_ppi = nrf52832->ppi;

    gpiote_step(nrf52832->gpiote); // TODO: Add to ticker instead
    bus_spi_step(nrf52832->bus_spi);

    int cycles = cpu_step(nrf52832->cpu);
    nrf52832->cycle_counter += cycles;

    ticker_hftick(nrf52832->ticker, cycles);

    return cycles;
}

cpu_t *nrf52832_get_cpu(NRF52832_t *chip)
{
    return chip->cpu;
}

bus_spi_t *nrf52832_get_spi(NRF52832_t *chip)
{
    return chip->bus_spi;
}

bus_i2c_t *nrf52832_get_i2c(NRF52832_t *chip)
{
    return chip->bus_i2c;
}

pins_t *nrf52832_get_pins(NRF52832_t *chip)
{
    return chip->pins;
}

void *nrf52832_get_peripheral(NRF52832_t *chip, uint8_t instance_id)
{
    uint32_t want_start = x(4000, 0000) | (instance_id << 12);
    memreg_t *region = memory_map_get_region(chip->mem, want_start);

    if (region)
        return memreg_get_userdata(region);

    return NULL;
}

size_t nrf52832_get_used_sram(NRF52832_t *nrf)
{
    size_t used = 0;
    for (size_t i = 0; i < nrf->sram_size; i++)
    {
        if (nrf->sram[i] != SRAM_FILL_BYTE)
            used++;
    }

    return used;
}

size_t nrf52832_get_sram_size(NRF52832_t *nrf)
{
    return nrf->sram_size;
}

bool nrf52832_flash_write(NRF52832_t *nrf, uint32_t addr, uint8_t value)
{
    if (addr < nrf->flash_size)
    {
        nrf->flash[addr] = value;
        return true;
    }

    return false;
}

uint64_t nrf52832_get_cycle_counter(NRF52832_t *nrf)
{
    return nrf->cycle_counter;
}

void nrf52832_reload_state(NRF52832_t *nrf)
{
    memory_map_do_operation_all(nrf->mem, OP_LOAD_DATA);
}
