#pragma once

#include "pinetime.h"

typedef struct gdb_t gdb_t;

typedef void (*step_emulation_t)(void *);

gdb_t *gdb_new(pinetime_t *pt, bool start_paused, step_emulation_t step, void *step_userdata);
void gdb_start(gdb_t *gdb);
uint16_t gdb_get_port(gdb_t *gdb);
