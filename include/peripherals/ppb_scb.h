#pragma once

#include <stdlib.h>

#include "memory.h"

typedef struct
{
    uint32_t cpacr;
} SCB_t;

OPERATION(scb)
{
    OP_ASSERT_SIZE(op, WORD);

    SCB_t *scb = (SCB_t *)userdata;

    if (offset == 0x88)
    {
        OP_RETURN_REG(scb->cpacr, WORD);
    }

    return false;
}

SCB_t *scb_new()
{
    SCB_t *scb = (SCB_t *)malloc(sizeof(SCB_t));
    return scb;
}

memreg_t *scb_memreg(SCB_t *scb)
{
    return memreg_new_operation(0xE000ED00, 0x8F, operation_scb, scb);
}
