#include "peripherals/ppb_dcb.h"

#include <stdlib.h>

#include "memory.h"

struct DCB_inst_t
{
    uint32_t demcr;
};

OPERATION(dcb)
{
    OP_ASSERT_SIZE(op, WORD);

    DCB_t *dcb = (DCB_t *)userdata;

    switch (offset)
    {
    case 0xC: // DEMCR
        OP_RETURN_REG(dcb->demcr, WORD);
    }

    return false;
}

DCB_t *dcb_new()
{
    return (DCB_t *)malloc(sizeof(DCB_t));
}

void dcb_reset(DCB_t *dcb)
{
    dcb->demcr = 0;
}
