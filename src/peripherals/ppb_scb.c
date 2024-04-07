#include "peripherals/ppb_scb.h"

#include <stdlib.h>

#include "memory.h"

struct SCB_inst_t
{
    uint32_t cpacr;
};

OPERATION(scb)
{
    OP_ASSERT_SIZE(op, WORD);

    SCB_t *scb = (SCB_t *)userdata;

    switch (offset)
    {
    case 0x88: // CPACR
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