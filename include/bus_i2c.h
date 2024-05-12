#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct bus_i2c_t bus_i2c_t;

typedef void (*i2c_write_f)(uint8_t *data, size_t data_size, void *userdata);
typedef size_t (*i2c_read_f)(uint8_t *data, size_t data_size, void *userdata);
typedef void (*i2c_reset_f)(void *userdata);

typedef struct
{
    void *userdata;
    i2c_write_f write;
    i2c_read_f read;
    i2c_reset_f reset;
} i2c_slave_t;

bus_i2c_t *i2c_new(uint8_t *ram, size_t ram_size);
void i2c_reset(bus_i2c_t *);
void i2c_free(bus_i2c_t *);
void i2c_add_slave(bus_i2c_t *, uint8_t address, i2c_slave_t slave);
void i2c_write(bus_i2c_t *, uint8_t address, uint32_t data_address, size_t data_size);
size_t i2c_read(bus_i2c_t *, uint8_t address, uint32_t data_address, size_t data_size);
