#include "peripherals/nrf52832/rng.h"

#include <stdlib.h>
#include <string.h>

struct RNG_inst_t
{
    uint32_t config;

    uint32_t inten;
    bool event_valrdy;
};

OPERATION(rng)
{
    RNG_t *rng = (RNG_t *)userdata;

    if (op == OP_RESET)
    {
        memset(rng, 0, sizeof(RNG_t));
        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
    case 0x000: // TASKS_START
        // Do nothing
        return MEMREG_RESULT_OK;
        
    case 0x100: // EVENTS_VALRDY
        OP_RETURN_REG(rng->event_valrdy, WORD);

    case 0x304: // INTENSET
        if (OP_IS_READ(op))
        {
            *value = rng->inten;
            return MEMREG_RESULT_OK;
        }

        rng->inten |= *value;
        return MEMREG_RESULT_OK;

    case 0x504: // CONFIG
        OP_RETURN_REG(rng->config, WORD);

    default:
        break;
    }

    return MEMREG_RESULT_UNHANDLED;
}

RNG_t *rng_new()
{
    RNG_t *rng = (RNG_t *)malloc(sizeof(RNG_t));
    return rng;
}
