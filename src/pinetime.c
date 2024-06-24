#include "pinetime.h"

#include "components/i2c/bma425.h"
#include "components/i2c/cst816s.h"
#include "components/i2c/hrs3300.h"
#include "components/spi/spinorflash.h"
#include "components/spi/st7789.h"

struct pinetime_t
{
    NRF52832_t *nrf;

    st7789_t *lcd;
    cst816s_t *touch;
    hrs3300_t *hrs;
    spinorflash_t *extflash;
};

pinetime_t *pinetime_new(const program_t *program)
{
    uint32_t initial_sp;
    program_write_to(program, (uint8_t *)&initial_sp, sizeof(initial_sp));

    size_t sram_size;
    if (initial_sp > 0x20010000)
        sram_size = 512 * 1024;
    else
        sram_size = NRF52832_SRAM_SIZE;

    pinetime_t *pt = malloc(sizeof(pinetime_t));
    pt->nrf = nrf52832_new(program, sram_size);
    pt->lcd = st7789_new();
    pt->touch = cst816s_new(nrf52832_get_pins(pt->nrf), PINETIME_CST816S_IRQ_PIN);
    pt->hrs = hrs3300_new();
    pt->extflash = spinorflash_new(PINETIME_EXTFLASH_SIZE, PINETIME_EXTFLASH_SECTOR_SIZE);

    bus_spi_add_slave(nrf52832_get_spi(pt->nrf), PINETIME_EXTFLASH_CS_PIN, spinorflash_get_slave(pt->extflash));
    bus_spi_add_slave(nrf52832_get_spi(pt->nrf), PINETIME_LCD_CS_PIN, st7789_get_slave(pt->lcd));
    i2c_add_slave(nrf52832_get_i2c(pt->nrf), PINETIME_CST816S_I2C_ADDR, cst816s_get_slave(pt->touch));
    i2c_add_slave(nrf52832_get_i2c(pt->nrf), PINETIME_BMA425_I2C_ADDR, bma425_new());
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

void pinetime_step(pinetime_t *pt)
{
    nrf52832_step(pt->nrf);
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
