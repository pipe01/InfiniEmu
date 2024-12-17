#include "peripherals/dcb.h"

#include <stdio.h>
#include <stdlib.h>

#include "memory.h"

struct DCB_inst_t
{
    uint32_t demcr;
};

OPERATION(dcb)
{
    DCB_t *dcb = userdata;

    if (op == OP_RESET)
    {
        dcb->demcr = 0x01000000;
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
    case 0x0: // DHCSR
        if (OP_IS_READ(op))
            *value = 0;
        printf("DHCSR: %08X\n", *value);
        return MEMREG_RESULT_OK;

    case 0xC: // DEMCR
        OP_RETURN_REG(dcb->demcr, WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

DCB_t *dcb_new(state_store_t *store)
{
    DCB_t *dcb = malloc(sizeof(DCB_t));

    state_store_register(store, STATE_KEY_DCB, dcb, sizeof(DCB_t));

    return dcb;
}
