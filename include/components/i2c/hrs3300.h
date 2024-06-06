#pragma once

#include "bus_i2c.h"

typedef struct hrs3300_t hrs3300_t;

hrs3300_t *hrs3300_new();
i2c_slave_t hrs3300_get_slave(hrs3300_t *);

void hrs3300_set_ch0(hrs3300_t *, uint32_t value);
void hrs3300_set_ch1(hrs3300_t *, uint32_t value);
