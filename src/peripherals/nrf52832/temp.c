#include "peripherals/nrf52832/temp.h"

#include <stdlib.h>
#include <string.h>

struct TEMP_inst_t
{
    uint32_t a[6];
    uint32_t b[6];
    uint32_t t[5];
};

OPERATION(temp)
{
    TEMP_t *temp = (TEMP_t *)userdata;

    if (op == OP_RESET)
    {
        memset(temp, 0, sizeof(TEMP_t));
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

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

NRF52_PERIPHERAL_CONSTRUCTOR(TEMP, temp)
{
    return malloc(sizeof(TEMP_t));
}

void temp_reset(TEMP_t *temp)
{
    
}