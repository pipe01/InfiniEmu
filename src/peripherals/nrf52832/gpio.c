#include "peripherals/nrf52832/gpio.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "memory.h"
#include "pins.h"

typedef union
{
    struct
    {
        unsigned int dir : 1;
        unsigned int input : 1;
        unsigned int pull : 2;
        unsigned int : 4;
        unsigned int drive : 3;
        unsigned int : 5;
        unsigned int sense : 2;
    };
    uint32_t value;
} pincnf_t;
static_assert(sizeof(pincnf_t) == 4);

struct GPIO_inst_t
{
    pins_t *pins;
};

static inline uint32_t read_gpios(pins_t *pins)
{
    uint32_t gpios = 0;

    for (int i = 0; i < 32; i++)
    {
        if (pins_is_set(pins, i))
            gpios |= 1 << i;
    }

    return gpios;
}

OPERATION(gpio)
{
    GPIO_t *gpio = (GPIO_t *)userdata;

    if (op == OP_RESET)
    {
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    // PIN_CNF[n]
    if (offset >= 0x700 && offset <= 0x77C)
    {
        uint32_t pin = (offset - 0x700) / 4;

        if (OP_IS_READ(op))
        {
            pincnf_t cnf = {0};
            cnf.dir = pins_is_input(gpio->pins, pin) ? 1 : 0;

            *value = cnf.value;
        }
        else
        {
            pincnf_t cnf = (pincnf_t){.value = *value};

            if (cnf.dir)
                pins_set_output(gpio->pins, pin);
            else
                pins_set_input(gpio->pins, pin);
        }

        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
    case 0x504: // OUT
        if (OP_IS_READ(op))
        {
            *value = read_gpios(gpio->pins);
        }
        else if (OP_IS_WRITE(op))
        {
            for (size_t i = 0; i < 32; i++)
            {
                if (*value & (1 << i))
                    pins_set(gpio->pins, i);
                else
                    pins_clear(gpio->pins, i);
            }
        }
        return MEMREG_RESULT_OK;

    case 0x510: // IN
        OP_ASSERT_READ(op);

        *value = read_gpios(gpio->pins);
        return MEMREG_RESULT_OK;

    case 0x508: // OUTSET
        if (OP_IS_READ(op))
        {
            *value = read_gpios(gpio->pins);
        }
        else if (OP_IS_WRITE(op))
        {
            for (size_t i = 0; i < 32; i++)
            {
                if (*value & (1 << i))
                    pins_set(gpio->pins, i);
            }
        }
        return MEMREG_RESULT_OK;

    case 0x50C: // OUTCLR
        if (OP_IS_READ(op))
        {
            *value = read_gpios(gpio->pins);
        }
        else if (OP_IS_WRITE(op))
        {
            for (size_t i = 0; i < 32; i++)
            {
                if (*value & (1 << i))
                    pins_clear(gpio->pins, i);
            }
        }
        return MEMREG_RESULT_OK;

    default:
        break;
    }

    return MEMREG_RESULT_UNHANDLED;
}

NRF52_PERIPHERAL_CONSTRUCTOR(GPIO, gpio)
{
    GPIO_t *gpio = (GPIO_t *)malloc(sizeof(GPIO_t));
    gpio->pins = ctx.pins;
    return gpio;
}
