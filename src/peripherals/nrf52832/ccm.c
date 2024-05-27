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

    OP_ASSERT_SIZE(op, WORD);

    return MEMREG_RESULT_OK;
}

CCM_t *ccm_new()
{
    return malloc(sizeof(CCM_t));
}
