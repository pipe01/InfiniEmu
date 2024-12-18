#include "pinetime.h"

#include "byte_util.h"
#include "components/i2c/bma425.h"
#include "components/i2c/cst816s.h"
#include "components/i2c/hrs3300.h"
#include "components/spi/spinorflash.h"
#include "components/spi/st7789.h"

struct pinetime_t
{
    NRF52832_t *nrf;
    state_store_t *state_store;

    st7789_t *lcd;
    cst816s_t *touch;
    hrs3300_t *hrs;
    spinorflash_t *extflash;
};

pinetime_t *pinetime_new(const program_t *program)
{
    uint32_t initial_sp;
    program_write_to(program, (uint8_t *)&initial_sp, sizeof(initial_sp));

    printf("Initial SP: 0x%08x\n", initial_sp);

    size_t sram_size = initial_sp - x(2000, 0000);
    if (sram_size < NRF52832_SRAM_SIZE)
        sram_size = NRF52832_SRAM_SIZE;

    printf("SRAM size: %ld bytes\n", sram_size);

    pinetime_t *pt = malloc(sizeof(pinetime_t));
    pt->state_store = state_store_new();
    pt->nrf = nrf52832_new(program, sram_size, pt->state_store);
    pt->lcd = st7789_new(pt->state_store);
    pt->touch = cst816s_new(nrf52832_get_pins(pt->nrf), pt->state_store, PINETIME_CST816S_IRQ_PIN);
    pt->hrs = hrs3300_new(pt->state_store);
    pt->extflash = spinorflash_new(pt->state_store, PINETIME_EXTFLASH_SIZE, PINETIME_EXTFLASH_SECTOR_SIZE);

    bus_spi_add_slave(nrf52832_get_spi(pt->nrf), PINETIME_EXTFLASH_CS_PIN, spinorflash_get_slave(pt->extflash));
    bus_spi_add_slave(nrf52832_get_spi(pt->nrf), PINETIME_LCD_CS_PIN, st7789_get_slave(pt->lcd));
    i2c_add_slave(nrf52832_get_i2c(pt->nrf), PINETIME_CST816S_I2C_ADDR, cst816s_get_slave(pt->touch));
    i2c_add_slave(nrf52832_get_i2c(pt->nrf), PINETIME_BMA425_I2C_ADDR, bma425_new(pt->state_store));
    i2c_add_slave(nrf52832_get_i2c(pt->nrf), PINETIME_HRS3300_I2C_ADDR, hrs3300_get_slave(pt->hrs));

    nrf52832_reset(pt->nrf);

    return pt;
}

void pinetime_free(pinetime_t *pt)
{
    free(pt);
}

void pinetime_reset(pinetime_t *pt)
{
    nrf52832_reset(pt->nrf);
}

int pinetime_step(pinetime_t *pt)
{
    return nrf52832_step(pt->nrf);
}

NRF52832_t *pinetime_get_nrf52832(pinetime_t *pt)
{
    return pt->nrf;
}

st7789_t *pinetime_get_st7789(pinetime_t *pt)
{
    return pt->lcd;
}

cst816s_t *pinetime_get_cst816s(pinetime_t *pt)
{
    return pt->touch;
}

hrs3300_t *pinetime_get_hrs3300(pinetime_t *pt)
{
    return pt->hrs;
}

spinorflash_t *pinetime_get_spinorflash(pinetime_t *pt)
{
    return pt->extflash;
}

uint8_t *pinetime_save_state(pinetime_t *pt, size_t *size)
{
    return state_store_save(pt->state_store, size);
}

bool pinetime_load_state(pinetime_t *pt, uint8_t *data, size_t size)
{
    if (state_store_load(pt->state_store, data, size))
    {
        nrf52832_reload_state(pt->nrf);
        return true;
    }

    return false;
}
