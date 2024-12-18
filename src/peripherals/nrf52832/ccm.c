#include "peripherals/nrf52832/ccm.h"

#include <stdlib.h>

struct CCM_inst_t
{
    uint32_t foo;
};

OPERATION(ccm)
{
    if (op == OP_RESET)
    {
        return MEMREG_RESULT_OK;
    }

    OP_IGNORE_LOAD_DATA
    OP_ASSERT_SIZE(op, WORD);

    return MEMREG_RESULT_OK;
}

NRF52_PERIPHERAL_CONSTRUCTOR(CCM, ccm)
{
    return malloc(sizeof(CCM_t));
}
