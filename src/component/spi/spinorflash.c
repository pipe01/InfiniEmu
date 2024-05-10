#include "components/spi/spinorflash.h"

#include <stdlib.h>

typedef struct
{
    uint32_t data;
} spinorflash_t;

void spinorflash_write(uint8_t *data, size_t data_size, void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;
    (void)flash;
}

uint8_t spinorflash_read(size_t *data_size, void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;
    (void)flash;

    abort();
}

void spinorflash_reset(void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;
    (void)flash;
}

spi_slave_t spinorflash_new(uint8_t csPin)
{
    spinorflash_t *flash = (spinorflash_t *)malloc(sizeof(spinorflash_t));

    return (spi_slave_t){
        .cs_pin = csPin,
        .userdata = flash,
        .read = spinorflash_read,
        .write = spinorflash_write,
        .reset = spinorflash_reset,
    };
}