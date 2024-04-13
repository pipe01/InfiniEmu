#include "peripherals/scb.h"

#include <stdlib.h>

#include "byte_util.h"
#include "memory.h"

OPERATION(scb)
{
    OP_ASSERT_SIZE(op, WORD);

    SCB_t *scb = (SCB_t *)userdata;

    switch (offset)
    {
    case 0x0C: // AIRCR
        OP_ASSERT_SIZE(op, WORD);

        if (OP_IS_READ(op))
        {
            *value = 0xFA050000;

            abort(); // TODO: Implement
        }
        else if (OP_IS_WRITE(op))
        {
            if ((*value & x(FFFF, 0000)) != x(05FA, 0000))
                return MEMREG_RESULT_INVALID_ACCESS;

            abort(); // TODO: Implement
        }

        break;

    case 0x88: // CPACR
        OP_RETURN_REG(scb->cpacr, WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

SCB_t *scb_new()
{
    return (SCB_t *)malloc(sizeof(SCB_t));
}

void scb_reset(SCB_t *scb)
{
    scb->cpacr = 0;
}