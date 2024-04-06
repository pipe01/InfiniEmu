#pragma once

#include <stdlib.h>

#include "memory.h"

typedef struct
{
    uint32_t foo;
} RADIO_t;

OPERATION(radio)
{
    OP_ASSERT_SIZE(op, WORD);

    // RADIO_t *radio = (RADIO_t *)userdata;

    switch (offset)
    {
        case 0x73C: // Unknown, do nothing
            return true;
    }

    return false;
}

RADIO_t *radio_new()
{
    return (RADIO_t *)malloc(sizeof(RADIO_t));
}

void radio_reset(RADIO_t *radio)
{
    
}