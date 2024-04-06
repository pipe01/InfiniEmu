#pragma once

#include <stdlib.h>

#include "memory.h"

typedef struct
{
    uint32_t foo;
} CLOCK_t;

OPERATION(clock)
{
    OP_ASSERT_SIZE(op, WORD);

    // CLOCK_t *clock = (CLOCK_t *)userdata;

    switch (offset)
    {
        case 0x53C: // Unknown, do nothing
            return true;
    }

    return false;
}

CLOCK_t *clock_new()
{
    return (CLOCK_t *)malloc(sizeof(CLOCK_t));
}

void clock_reset(CLOCK_t *clock)
{
    
}