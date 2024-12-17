#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pins.h"
#include "state_store.h"

typedef struct bus_spi_t bus_spi_t;

typedef void (*spi_write_f)(uint8_t byte, void *userdata);
typedef uint8_t (*spi_read_f)(void *userdata);
typedef void (*spi_reset_f)(void *userdata);
typedef void (*spi_cs_changed_f)(bool selected, void *userdata);

typedef enum
{
    SPI_RESULT_OK = 0,
    SPI_RESULT_NO_SELECTED,
} spi_result_t;

typedef struct
{
    void *userdata;
    spi_write_f write;
    spi_read_f read;
    spi_reset_f reset;
    spi_cs_changed_f cs_changed;
} spi_slave_t;

bus_spi_t *bus_spi_new(pins_t *pins, uint8_t *ram, size_t ram_size, state_store_t *store);
void bus_spi_reset(bus_spi_t *);
void bus_spi_free(bus_spi_t *);
void bus_spi_step(bus_spi_t *);
void bus_spi_add_slave(bus_spi_t *, uint8_t cs_pin, spi_slave_t slave);
spi_result_t bus_spi_write_dma(bus_spi_t *, uint32_t address, size_t size);
spi_result_t bus_spi_write(bus_spi_t *, uint8_t byte);
size_t bus_spi_read_dma(bus_spi_t *, uint32_t address, size_t size);
bool bus_spi_read(bus_spi_t *, uint8_t *data);
