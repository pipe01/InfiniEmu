#include "components/spi/spinorflash.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

enum
{
    COMMAND_READ = 0x03, // Read Data Bytes
    COMMAND_RDID = 0x9F, // Read Identification
    COMMAND_RDI = 0xAB,  // Release from Deep Power-Down and Read Device ID
};

#define MAX_COMMAND_SIZE 32

typedef struct
{
    uint8_t *data;
    size_t size;

    uint8_t last_command[MAX_COMMAND_SIZE];
    size_t last_command_size;
} spinorflash_t;

void spinorflash_write(uint8_t *data, size_t data_size, void *userdata)
{
    if (data_size > MAX_COMMAND_SIZE)
    {
        printf("SPI flash command too long: %zu\n", data_size);
        abort();
    }

    spinorflash_t *flash = (spinorflash_t *)userdata;

    memcpy(flash->last_command, data, data_size);
    flash->last_command_size = data_size;

#ifdef SPI_FLASH_DEBUG
    printf("SPI flash got data: ");
    for (size_t i = 0; i < data_size; i++)
    {
        printf("%02X", data[i]);
        if (i < data_size - 1)
            printf("-");
    }
    printf("\n");
#endif
}

size_t spinorflash_read(uint8_t *data, size_t data_size, void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;

    switch (flash->last_command[0])
    {
    case COMMAND_READ:
    {
        assert(flash->last_command_size == 4);
        uint32_t offset = (flash->last_command[1] << 16) | (flash->last_command[2] << 8) | flash->last_command[3];
        memcpy(data, flash->data + offset, data_size);
        return data_size;
    }

    case COMMAND_RDID:
        assert(data_size >= 3);

        // Dummy data
        data[0] = 0xA5;
        data[1] = 0xA5;
        data[2] = 0xA5;
        return 3;

    case COMMAND_RDI:
        assert(data_size >= 1);

        // Dummy data
        data[0] = 0xA5;
        return 1;
    }

    printf("Unknown SPI flash command: %02X\n", flash->last_command[0]);
    abort();
}

void spinorflash_reset(void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;
    (void)flash;
}

spi_slave_t spinorflash_new(size_t size, uint8_t csPin)
{
    spinorflash_t *flash = (spinorflash_t *)malloc(sizeof(spinorflash_t));
    flash->data = (uint8_t *)malloc(size);

    return (spi_slave_t){
        .cs_pin = csPin,
        .userdata = flash,
        .read = spinorflash_read,
        .write = spinorflash_write,
        .reset = spinorflash_reset,
    };
}