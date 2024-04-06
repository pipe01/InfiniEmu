#pragma once

#include <stdlib.h>

#include "memory.h"

typedef struct
{
    uint32_t cpacr;
} COMP_t;

OPERATION(comp)
{
    OP_ASSERT_SIZE(op, WORD);

    // COMP_t *comp = (COMP_t *)userdata;

    switch (offset)
    {
        case 0x540: // Unknown, do nothing
            return true;
    }

    return false;
}

COMP_t *comp_new()
{
    return (COMP_t *)malloc(sizeof(COMP_t));
}

void comp_reset(COMP_t *comp)
{
    comp->cpacr = 0;
}
