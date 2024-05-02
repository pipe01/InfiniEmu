#include "peripherals/nrf52832/gpio.h"

#include <stdlib.h>
#include <string.h>

#include "memory.h"

struct GPIO_inst_t
{
    uint32_t out;
    uint32_t dir;
    uint32_t dout;
    uint32_t din;
    uint32_t pin_cnf[32];
};

OPERATION(gpio)
{
    GPIO_t *gpio = (GPIO_t *)userdata;
    
    OP_ASSERT_SIZE(op, WORD);

    if (op == OP_RESET)
    {
        memset(gpio, 0, sizeof(GPIO_t));
        return MEMREG_RESULT_OK;
    }

    // PIN_CNF[n]
    if (offset >= 0x700 && offset <= 0x77C)
    {
        uint32_t pin = (offset - 0x700) / 4;

        OP_RETURN_REG(gpio->pin_cnf[pin], WORD);
    }

    switch (offset)
    {
    case 0x504: // OUT
        if (OP_IS_READ(op))
            *value = gpio->out;
        else if (OP_IS_WRITE(op))
            gpio->out = *value;
        return MEMREG_RESULT_OK;

    case 0x508: // OUTSET
        if (OP_IS_READ(op))
            *value = gpio->out;
        else if (OP_IS_WRITE(op))
            gpio->out |= *value;
        return MEMREG_RESULT_OK;

    case 0x50C: // OUTCLR
        if (OP_IS_READ(op))
            *value = gpio->out;
        else if (OP_IS_WRITE(op))
            gpio->out &= ~*value;
        return MEMREG_RESULT_OK;

    default:
        break;
    }

    return MEMREG_RESULT_UNHANDLED;
}

GPIO_t *gpio_new()
{
    return (GPIO_t *)malloc(sizeof(GPIO_t));
}
