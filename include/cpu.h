#pragma once

#include <stdint.h>

typedef struct
{
    uint32_t pc;
} cpu_t;

cpu_t *cpu_new();
