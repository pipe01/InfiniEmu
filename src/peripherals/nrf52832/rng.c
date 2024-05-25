#include "peripherals/nrf52832/rng.h"

#include <stdlib.h>
#include <string.h>

struct RNG_inst_t
{
    uint32_t config;

    uint32_t inten;
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
        OP_TASK(0x000, PPI_TASK_RNG_START)
        OP_EVENT(0x100, PPI_EVENT_RNG_VALRDY)

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
