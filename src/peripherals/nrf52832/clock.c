#include "peripherals/nrf52832/clock.h"

#include <stdlib.h>
#include <string.h>

#include "memory.h"
#include "nrf52832.h"
#include "peripherals/nrf52832/ppi.h"

struct CLOCK_inst_t
{
    uint32_t lfclk_source;
    bool lfclk_running;

    bool hfclk_running;

    uint32_t inten;
};

enum
{
    TASKS_HFCLKSTART = 0x000,
    TASKS_HFCLKSTOP = 0x004,
    TASKS_LFCLKSTART = 0x008,
    TASKS_LFCLKSTOP = 0x00C,
    TASKS_CAL = 0x010,
    TASKS_CTSTART = 0x014,
    TASKS_CTSTOP = 0x018,
    EVENTS_HFCLKSTARTED = 0x100,
    EVENTS_LFCLKSTARTED = 0x104,
    EVENTS_DONE = 0x10C,
    EVENTS_CTTO = 0x110,
};

OPERATION(clock)
{
    CLOCK_t *clock = (CLOCK_t *)userdata;

    if (op == OP_RESET)
    {
        memset(clock, 0, sizeof(CLOCK_t));
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(TASKS_HFCLKSTART)
        OP_TASK(TASKS_LFCLKSTART)
        OP_EVENT(EVENTS_HFCLKSTARTED)
        OP_EVENT(EVENTS_LFCLKSTARTED)
        OP_EVENT(EVENTS_DONE)
        OP_EVENT(EVENTS_CTTO)

    case 0x538: // CTIV
        OP_ASSERT_WRITE(op);

        // Do nothing
        return MEMREG_RESULT_OK;

    case 0x304: // INTENSET
        if (OP_IS_READ(op))
            *value = clock->inten;
        else
            clock->inten |= *value;
        return MEMREG_RESULT_OK;

    case 0x308: // INTENCLR
        if (OP_IS_READ(op))
            *value = clock->inten;
        else
            clock->inten &= ~*value;
        return MEMREG_RESULT_OK;

    case 0x418: // LFCLKSTAT
        OP_ASSERT_READ(op);

        *value = (clock->lfclk_source & 3) | (clock->lfclk_running ? 1 << 16 : 0);
        return MEMREG_RESULT_OK;

    case 0x518: // LFCLKSRC
        OP_RETURN_REG(clock->lfclk_source, WORD);

    case 0x53C: // Magic, do nothing
        return MEMREG_RESULT_OK;

    case 0xEE4: // Magic
        if (OP_IS_READ(op))
            *value = 0x4F;

        return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

PPI_TASK_HANDLER(clock_task_handler)
{
    CLOCK_t *clock = userdata;

    switch (task)
    {
    case TASK_ID(TASKS_HFCLKSTART):
        clock->hfclk_running = true;
        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_HFCLKSTARTED));
        break;

    case TASK_ID(TASKS_LFCLKSTART):
        clock->lfclk_running = true;
        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_LFCLKSTARTED));
        break;

    default:
        abort();
    }
}

NRF52_PERIPHERAL_CONSTRUCTOR(CLOCK, clock)
{
    CLOCK_t *clock = (CLOCK_t *)malloc(sizeof(CLOCK_t));

    ppi_add_peripheral(ctx.ppi, ctx.id, clock_task_handler, clock);

    return clock;
}
