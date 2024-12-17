#pragma once

#include "bus_i2c.h"
#include "state_store.h"

i2c_slave_t bma425_new(state_store_t *store);
