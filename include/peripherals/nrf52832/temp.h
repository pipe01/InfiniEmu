#pragma once

#include <stdlib.h>

#include "memory.h"

typedef struct
{
    uint32_t a[6];
    uint32_t b[6];
    uint32_t t[5];
} TEMP_t;

OPERATION(temp)
{
    OP_ASSERT_SIZE(op, WORD);

    TEMP_t *temp = (TEMP_t *)userdata;

    if (offset >= 0x520 && offset <= 0x534)
    {
        OP_RETURN_REG(temp->a[(offset - 0x520) / 4], WORD);
    }
    if (offset >= 0x540 && offset <= 0x554)
    {
        OP_RETURN_REG(temp->b[(offset - 0x540) / 4], WORD);
    }
    if (offset >= 0x560 && offset <= 0x570)
    {
        OP_RETURN_REG(temp->t[(offset - 0x560) / 4], WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

TEMP_t *temp_new()
{
    return (TEMP_t *)malloc(sizeof(TEMP_t));
}

void temp_reset(TEMP_t *temp)
{
    
}