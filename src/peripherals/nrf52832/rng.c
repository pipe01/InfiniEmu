#include "peripherals/nrf52832/rng.h"

#include "nrf52832.h"
#include "peripherals/nrf52832/ppi.h"

#include <stdlib.h>
#include <string.h>

enum
{
    TASKS_START = 0x000,
    TASKS_STOP = 0x004,
    EVENTS_VALRDY = 0x100,
};

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
        OP_TASK(TASKS_START)
        OP_EVENT(EVENTS_VALRDY)

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

PPI_TASK_HANDLER(rng_task_cb)
{
    // TODO: Implement
}

NRF52_PERIPHERAL_CONSTRUCTOR(RNG, rng)
{
    RNG_t *rng = (RNG_t *)malloc(sizeof(RNG_t));

    ppi_add_peripheral(ctx.ppi, ctx.id, rng_task_cb, rng);

    return rng;
}
