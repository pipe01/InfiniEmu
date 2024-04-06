#pragma once

#include "nrf52832.h"

typedef struct gdb_inst_t gdb_t;

gdb_t *gdb_new(NRF52832_t *nrf52832);
void gdb_start(gdb_t *gdb);
