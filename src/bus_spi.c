#include "bus_spi.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arm.h"
#include "byte_util.h"
#include "fault.h"
#include "peripherals/nrf52832/gpio.h"

#define MAX_SLAVES 32

struct bus_spi_t
{
    uint8_t *ram;
    size_t ram_size;

    bool was_selected[MAX_SLAVES];
    spi_slave_t *slaves[MAX_SLAVES];
    uint8_t slave_pin[MAX_SLAVES];
    size_t slave_count;

    pins_t *pins;
};

bus_spi_t *bus_spi_new(pins_t *pins, uint8_t *ram, size_t ram_size)
{
    bus_spi_t *spi = (bus_spi_t *)calloc(1, sizeof(bus_spi_t));
    spi->pins = pins;
    spi->ram = ram;
    spi->ram_size = ram_size;
    return spi;
}

void bus_spi_reset(bus_spi_t *spi)
{
    for (size_t i = 0; i < spi->slave_count; i++)
    {
        spi->slaves[i]->reset(spi->slaves[i]->userdata);
    }
}

void bus_spi_free(bus_spi_t *spi)
{
    for (size_t i = 0; i < spi->slave_count; i++)
    {
        free(spi->slaves[i]);
    }

    free(spi);
}

void bus_spi_step(bus_spi_t *spi)
{
    for (size_t i = 0; i < spi->slave_count; i++)
    {
        bool selected = !pins_is_set(spi->pins, spi->slave_pin[i]);

        if ((selected != spi->was_selected[i]) && spi->slaves[i]->cs_changed)
        {
            spi->slaves[i]->cs_changed(selected, spi->slaves[i]->userdata);
        }

        spi->was_selected[i] = selected;
    }
}

void bus_spi_add_slave(bus_spi_t *spi, uint8_t cs_pin, spi_slave_t slave)
{
    // TODO: Check too many slaves

    spi_slave_t *copy = (spi_slave_t *)malloc(sizeof(spi_slave_t));
    memcpy(copy, &slave, sizeof(spi_slave_t));

    spi->slaves[spi->slave_count] = copy;
    spi->slave_pin[spi->slave_count] = cs_pin;

    spi->slave_count++;
}

spi_result_t bus_spi_write_dma(bus_spi_t *spi, uint32_t address, size_t size)
{
    if (address < ARM_SRAM_START || address >= ARM_SRAM_END) // TODO: Check end too
    {
        printf("Invalid EasyDMA address 0x%08X\n", address);
        fault_take(FAULT_DMA_INVALID_ADDRESS);
    }

    uint32_t offset = address - ARM_SRAM_START;

    return bus_spi_write(spi, spi->ram + offset, size);
}

spi_result_t bus_spi_write(bus_spi_t *spi, const uint8_t *data, size_t size)
{
    bool handled = false;

    for (size_t i = 0; i < spi->slave_count; i++)
    {
        if (!pins_is_set(spi->pins, spi->slave_pin[i]))
        {
            spi->slaves[i]->write(data, size, spi->slaves[i]->userdata);
            handled = true;
        }
    }

    return handled ? SPI_RESULT_OK : SPI_RESULT_NO_SELECTED;
}

size_t bus_spi_read_dma(bus_spi_t *spi, uint32_t address, size_t size)
{
    if (address < ARM_SRAM_START || address >= ARM_SRAM_END) // TODO: Check end too
    {
        printf("Invalid EasyDMA address 0x%08X\n", address);
        fault_take(FAULT_DMA_INVALID_ADDRESS);
    }

    uint32_t offset = address - ARM_SRAM_START;

    return bus_spi_read(spi, spi->ram + offset, size);
}

size_t bus_spi_read(bus_spi_t *spi, uint8_t *data, size_t size)
{
    for (size_t i = 0; i < spi->slave_count; i++)
    {
        if (!pins_is_set(spi->pins, spi->slave_pin[i]))
        {
            size_t read = spi->slaves[i]->read(data, size, spi->slaves[i]->userdata);
            return read;
        }
    }

    return 0;
}
