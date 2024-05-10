#include "components/spi/spinorflash.h"

#include <assert.h>
#include <stdlib.h>

enum
{
    COMMAND_RDID = 0x9F, // Read Identification
};

typedef struct
{
    uint32_t data;

    uint8_t last_command;
} spinorflash_t;

void spinorflash_write(uint8_t *data, size_t data_size, void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;
    flash->last_command = data[0];
}

size_t spinorflash_read(uint8_t *data, size_t data_size, void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;
    
    switch (flash->last_command)
    {
    case COMMAND_RDID:
        assert(data_size >= 3);

        // Dummy data
        data[0] = 0xA5;
        data[1] = 0xA5;
        data[2] = 0xA5;
        return 3;
    }

    return 0;
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