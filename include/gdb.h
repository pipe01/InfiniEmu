#pragma once

#include "pinetime.h"

typedef struct gdb_t gdb_t;

gdb_t *gdb_new(pinetime_t *pt, bool start_paused);
void gdb_start(gdb_t *gdb);
