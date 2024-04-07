#pragma once

#include "nrf52832.h"

typedef struct gdb_inst_t gdb_t;

gdb_t *gdb_new(NRF52832_t *nrf52832, bool start_paused);
void gdb_start(gdb_t *gdb);

void gdb_wait_for_connection(gdb_t *gdb);
void gdb_wait_for_unpause(gdb_t *gdb);
void gdb_wait_for_pause(gdb_t *gdb);
void gdb_check_breakpoint(gdb_t *gdb, uint32_t addr);
