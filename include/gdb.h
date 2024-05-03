#pragma once

#include "nrf52832.h"

typedef struct gdb_t gdb_t;

gdb_t *gdb_new(NRF52832_t *nrf52832, bool start_paused);
void gdb_start(gdb_t *gdb);
