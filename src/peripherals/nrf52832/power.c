#include <stdlib.h>

#include "peripherals/nrf52832/power.h"
#include "arm.h"

struct POWER_inst_t
{
    nrf_resetreason resetreason;
};

OPERATION(power)
{
    OP_ASSERT_SIZE(op, WORD);

    POWER_t *power = (POWER_t *)userdata;

    switch (offset)
    {
        case 0x400:
            if (OP_IS_READ(op))
                *value = power->resetreason;
            else
                power->resetreason &= ~*value;

            return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

POWER_t *power_new()
{
    return (POWER_t *)malloc(sizeof(POWER_t));
}

void power_reset(POWER_t *power)
{
    power->resetreason = RESETREASON_RESETPIN;
}