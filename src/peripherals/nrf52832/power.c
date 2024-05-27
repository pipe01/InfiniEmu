#include <stdlib.h>

#include "peripherals/nrf52832/power.h"
#include "arm.h"

struct POWER_inst_t
{
    nrf_resetreason resetreason;
};

OPERATION(power)
{
    POWER_t *power = (POWER_t *)userdata;

    if (op == OP_RESET)
    {
        power->resetreason = RESETREASON_SREQ;
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        case 0x400: // RESETREAS
            if (OP_IS_READ(op))
                *value = power->resetreason;
            else
                power->resetreason &= ~*value;

            return MEMREG_RESULT_OK;
        
        case 0x578: // DCDCEN
            // Do nothing
            return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

NRF52_PERIPHERAL_CONSTRUCTOR(POWER, power)
{
    return malloc(sizeof(POWER_t));
}
