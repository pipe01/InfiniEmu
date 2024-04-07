#pragma once

#include <stdlib.h>

#include "memory.h"

typedef struct NVIC_inst_t NVIC_t;

OPERATION(nvic);
NVIC_t *nvic_new();
void nvic_reset(NVIC_t *nvic);