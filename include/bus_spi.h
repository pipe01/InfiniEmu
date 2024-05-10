#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pins.h"

typedef struct bus_spi_t bus_spi_t;

typedef void (*spi_write_f)(uint8_t *data, size_t data_size, void *userdata);
typedef uint8_t (*spi_read_f)(size_t *data_size, void *userdata);
typedef void (*spi_reset_f)(void *userdata);

typedef enum
{
    SPI_RESULT_OK = 0,
    SPI_RESULT_NO_SELECTED,
} spi_result_t;

typedef struct
{
    uint8_t cs_pin;
    void *userdata;
    spi_write_f write;
    spi_read_f read;
    spi_reset_f reset;
} spi_slave_t;

bus_spi_t *spi_new(pins_t *pins);
void spi_reset(bus_spi_t *);
void spi_free(bus_spi_t *);
void spi_add_slave(bus_spi_t *, spi_slave_t slave);
spi_result_t spi_write(bus_spi_t *, uint8_t *data, size_t data_size);
