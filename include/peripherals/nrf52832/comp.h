#pragma once

#include <stdlib.h>

#include "memory.h"

typedef struct
{
    uint32_t foo;
} COMP_t;

OPERATION(comp)
{
    if (op == OP_RESET)
        return MEMREG_RESULT_OK;

    OP_ASSERT_SIZE(op, WORD);

    // COMP_t *comp = (COMP_t *)userdata;

    switch (offset)
    {
    case 0x540: // Unknown, do nothing
        return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

COMP_t *comp_new()
{
    return (COMP_t *)malloc(sizeof(COMP_t));
}

void comp_reset(COMP_t *comp)
{
}
