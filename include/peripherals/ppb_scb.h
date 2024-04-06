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
    return (SCB_t *)malloc(sizeof(SCB_t));
}

void scb_reset(SCB_t *scb)
{
    scb->cpacr = 0;
}