#include "peripherals/nrf52832/comp.h"

struct COMP_inst_t
{
    uint32_t foo;
};

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

NRF52_PERIPHERAL_CONSTRUCTOR(COMP, comp)
{
    return malloc(sizeof(COMP_t));
}

void comp_reset(COMP_t *comp)
{
}
