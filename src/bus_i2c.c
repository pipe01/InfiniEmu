#include "bus_i2c.h"

#include <stdlib.h>
#include <string.h>

#include "arm.h"

#define MAX_SLAVES 256

struct bus_i2c_t
{
    uint8_t *ram;
    size_t ram_size;

    i2c_slave_t *slaves[MAX_SLAVES];
};

bus_i2c_t *i2c_new(uint8_t *ram, size_t ram_size)
{
    bus_i2c_t *i2c = (bus_i2c_t *)calloc(1, sizeof(bus_i2c_t));
    i2c->ram = ram;
    i2c->ram_size = ram_size;
    return i2c;
}

void i2c_reset(bus_i2c_t *i2c)
{
    for (size_t i = 0; i < MAX_SLAVES; i++)
    {
        if (i2c->slaves[i])
            i2c->slaves[i]->reset(i2c->slaves[i]->userdata);
    }
}

void i2c_free(bus_i2c_t *i2c)
{
    for (size_t i = 0; i < MAX_SLAVES; i++)
    {
        if (i2c->slaves[i])
            free(i2c->slaves[i]);
    }

    free(i2c);
}

void i2c_add_slave(bus_i2c_t *i2c, uint8_t address, i2c_slave_t slave)
{
    if (i2c->slaves[address])
        abort();

    i2c_slave_t *copy = (i2c_slave_t *)malloc(sizeof(i2c_slave_t));
    memcpy(copy, &slave, sizeof(i2c_slave_t));

    i2c->slaves[address] = copy;
}

void i2c_write(bus_i2c_t *i2c, uint8_t address, uint32_t data_address, size_t data_size)
{
    if (!i2c->slaves[address])
        abort();

    if (data_address < ARM_SRAM_START || data_address >= ARM_SRAM_END) // TODO: Check end too
    {
        printf("Invalid EasyDMA address 0x%08X\n", data_address);
        abort();
    }

    uint32_t offset = data_address - ARM_SRAM_START;

    i2c->slaves[address]->write(i2c->ram + offset, data_size, i2c->slaves[address]->userdata);
}

size_t i2c_read(bus_i2c_t *i2c, uint8_t address, uint32_t data_address, size_t data_size)
{
    if (!i2c->slaves[address])
        abort();

    if (data_address < ARM_SRAM_START || data_address >= ARM_SRAM_END) // TODO: Check end too
    {
        printf("Invalid EasyDMA address 0x%08X\n", data_address);
        abort();
    }

    uint32_t offset = data_address - ARM_SRAM_START;

    return i2c->slaves[address]->read(i2c->ram + offset, data_size, i2c->slaves[address]->userdata);
}
