#include "peripherals/nrf52832/clock.h"

#include <stdlib.h>
#include <string.h>

#include "memory.h"

struct CLOCK_inst_t
{
    uint32_t lfclk_source;
    bool lfclk_running;

    uint32_t inten;
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
        OP_TASK(0x008, PPI_TASK_CLOCK_LFCLKSTART)
        OP_EVENT(0x104, PPI_EVENT_CLOCK_LFCLKSTARTED)

    case 0x10C: // EVENTS_DONE
    case 0x110: // EVENTS_CTTO
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

void clock_lfclkstart(ppi_tasks_t task, void *userdata)
{
    ((CLOCK_t *)userdata)->lfclk_running = true;

    ppi_fire_event(current_ppi, PPI_EVENT_CLOCK_LFCLKSTARTED);
}

CLOCK_t *clock_new()
{
    CLOCK_t *clock = (CLOCK_t *)malloc(sizeof(CLOCK_t));

    ppi_on_task(current_ppi, PPI_TASK_CLOCK_LFCLKSTART, (ppi_task_cb_t)clock_lfclkstart, clock);

    return clock;
}
