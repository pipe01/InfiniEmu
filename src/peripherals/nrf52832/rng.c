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

typedef union
{
    struct
    {
        unsigned int VALRDY : 1;
    };
    uint32_t value;
} inten_t;

struct RNG_inst_t
{
    cpu_t **cpu;
    PPI_t *ppi;

    uint32_t value;

    bool running;
    uint32_t config;

    inten_t inten;
};

static inline void rng_new_value(RNG_t *rng)
{
    rng->value = (uint32_t)rand();

    ppi_fire_event(rng->ppi, INSTANCE_RNG, EVENT_ID(EVENTS_VALRDY), rng->inten.VALRDY);
}

OPERATION(rng)
{
    RNG_t *rng = (RNG_t *)userdata;

    if (op == OP_RESET)
    {
        *rng = (RNG_t){
            .cpu = rng->cpu,
            .ppi = rng->ppi,
        };
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(TASKS_START)
        OP_TASK(TASKS_STOP)
        OP_EVENT(EVENTS_VALRDY)

        OP_INTENSET(rng)
        OP_INTENCLR(rng)

    case 0x504: // CONFIG
        OP_RETURN_REG(rng->config, WORD);

    case 0x508:
        OP_ASSERT_READ(op);

        *value = rng->value;

        if (rng->running)
            rng_new_value(rng);

        return MEMREG_RESULT_OK;

    default:
        break;
    }

    return MEMREG_RESULT_UNHANDLED;
}

PPI_TASK_HANDLER(rng_task_cb)
{
    RNG_t *rng = (RNG_t *)userdata;

    switch (task)
    {
    case TASK_ID(TASKS_START):
        rng->running = true;
        rng_new_value(rng);
        break;

    case TASK_ID(TASKS_STOP):
        rng->running = false;
        break;

    default:
        break;
    }
}

NRF52_PERIPHERAL_CONSTRUCTOR(RNG, rng)
{
    RNG_t *rng = (RNG_t *)malloc(sizeof(RNG_t));
    rng->cpu = ctx.cpu;
    rng->ppi = ctx.ppi;

    ppi_add_peripheral(ctx.ppi, ctx.id, rng_task_cb, rng);

    return rng;
}
