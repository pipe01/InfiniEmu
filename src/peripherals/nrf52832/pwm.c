#include "peripherals/nrf52832/pwm.h"

struct PWM_inst_t
{
    char dummy;
};

OPERATION(pwm)
{
    if (op == OP_RESET)
    {
        return MEMREG_RESULT_OK;
    }

    OP_IGNORE_LOAD_DATA
    OP_ASSERT_SIZE(op, WORD);

    return MEMREG_RESULT_OK;
}

NRF52_PERIPHERAL_CONSTRUCTOR(PWM, pwm)
{
    return malloc(sizeof(PWM_t));
}
