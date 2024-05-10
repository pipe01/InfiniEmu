#include "bus_spi.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arm.h"
#include "byte_util.h"
#include "peripherals/nrf52832/gpio.h"

#define MAX_SLAVES 32

struct bus_spi_t
{
    uint8_t *ram;
    size_t ram_size;

    spi_slave_t *slaves[MAX_SLAVES];
    size_t slave_count;

    pins_t *pins;
};

bus_spi_t *spi_new(pins_t *pins, uint8_t *ram, size_t ram_size)
{
    bus_spi_t *spi = (bus_spi_t *)calloc(1, sizeof(bus_spi_t));
    spi->pins = pins;
    spi->ram = ram;
    spi->ram_size = ram_size;
    return spi;
}

void spi_reset(bus_spi_t *spi)
{
    for (size_t i = 0; i < spi->slave_count; i++)
    {
        spi->slaves[i]->reset(spi->slaves[i]->userdata);
    }
}

void spi_free(bus_spi_t *spi)
{
    for (size_t i = 0; i < spi->slave_count; i++)
    {
        free(spi->slaves[i]);
    }

    free(spi);
}

void spi_add_slave(bus_spi_t *spi, spi_slave_t slave)
{
    // TODO: Check too many slaves

    spi_slave_t *copy = (spi_slave_t *)malloc(sizeof(spi_slave_t));
    memcpy(copy, &slave, sizeof(spi_slave_t));

    spi->slaves[spi->slave_count++] = copy;
}

spi_result_t spi_write(bus_spi_t *spi, uint32_t address, size_t size)
{
    if (address < ARM_SRAM_START || address >= ARM_SRAM_END) // TODO: Check end too
    {
        printf("Invalid EasyDMA address 0x%08X\n", address);
        abort();
    }

    uint32_t offset = address - ARM_SRAM_START;

    for (size_t i = 0; i < spi->slave_count; i++)
    {
        if (pins_is_set(spi->pins, spi->slaves[i]->cs_pin))
            spi->slaves[i]->write(spi->ram + offset, size, spi->slaves[i]->userdata);
    }

    return SPI_RESULT_OK;
}
