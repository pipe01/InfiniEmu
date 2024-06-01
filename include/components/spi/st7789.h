#pragma once

#include "bus_spi.h"

typedef struct st7789_t st7789_t;

#define DISPLAY_WIDTH 240
#define DISPLAY_HEIGHT 320
#define BYTES_PER_PIXEL 2 // We assume 16bpp format

st7789_t* st7789_new();
spi_slave_t st7789_get_slave(st7789_t *);

void st7789_read_screen(st7789_t *, uint8_t *data, size_t width, size_t height);
bool st7789_is_sleeping(st7789_t *);
