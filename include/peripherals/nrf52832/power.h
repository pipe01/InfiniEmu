#pragma once

#include <stdlib.h>

#include "memory.h"

typedef struct
{
    uint32_t foo;
} POWER_t;

OPERATION(power)
{
    OP_ASSERT_SIZE(op, WORD);

    // POWER_t *power = (POWER_t *)userdata;

    switch (offset)
    {
    }

    return false;
}

POWER_t *power_new()
{
    return (POWER_t *)malloc(sizeof(POWER_t));
}

void power_reset(POWER_t *power)
{
    
}