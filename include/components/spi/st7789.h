#pragma once

#include "bus_spi.h"

typedef struct st7789_t st7789_t;

#define DISPLAY_WIDTH 240
#define DISPLAY_HEIGHT 240

st7789_t* st7789_new();
spi_slave_t st7789_get_slave(st7789_t *);
