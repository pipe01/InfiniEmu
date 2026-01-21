#pragma once

#include "pinetime.h"

typedef struct bluetooth_t bluetooth_t;

bluetooth_t *bluetooth_new(pinetime_t *pt);
void bluetooth_run(bluetooth_t *);
