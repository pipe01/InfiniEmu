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
};

pinetime_t *pinetime_new(const uint8_t *program, size_t program_size, bool big_ram)
{
    pinetime_t *pt = (pinetime_t *)malloc(sizeof(pinetime_t));
    pt->nrf = nrf52832_new(program, program_size, big_ram ? 512 * 1024 : NRF52832_SRAM_SIZE);
    pt->lcd = st7789_new();

    spi_add_slave(nrf52832_get_spi(pt->nrf), PINETIME_EXTFLASH_CS_PIN, spinorflash_new(PINETIME_EXTFLASH_SIZE, PINETIME_EXTFLASH_SECTOR_SIZE));
    spi_add_slave(nrf52832_get_spi(pt->nrf), PINETIME_LCD_CS_PIN, st7789_get_slave(pt->lcd));
    i2c_add_slave(nrf52832_get_i2c(pt->nrf), PINETIME_CST816S_I2C_ADDR, cst816s_new());
    i2c_add_slave(nrf52832_get_i2c(pt->nrf), PINETIME_BMA425_I2C_ADDR, bma425_new());
    i2c_add_slave(nrf52832_get_i2c(pt->nrf), PINETIME_HRS3300_I2C_ADDR, hrs3300_new());

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
