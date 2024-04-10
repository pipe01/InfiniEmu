#include "peripherals/nrf52832/clock.h"

#include <stdlib.h>
#include <string.h>

#include "memory.h"

struct CLOCK_inst_t
{
    bool events_lfclkstarted;

    uint32_t lfclk_source;
    bool lfclk_running;

    uint32_t inten;
};

OPERATION(clock)
{
    OP_ASSERT_SIZE(op, WORD);

    CLOCK_t *clock = (CLOCK_t *)userdata;

    switch (offset)
    {
    case 0x008: // TASKS_LFCLKSTART
        OP_ASSERT_WRITE(op);

        clock->lfclk_running = true;
        return MEMREG_RESULT_OK;

    case 0x104: // EVENTS_LFCLKSTARTED
        if (OP_IS_READ(op))
            *value = clock->events_lfclkstarted ? 1 : 0;
        else if (OP_IS_WRITE(op))
            clock->events_lfclkstarted = *value;

        return MEMREG_RESULT_OK;

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

CLOCK_t *clock_new()
{
    return (CLOCK_t *)malloc(sizeof(CLOCK_t));
}

void clock_reset(CLOCK_t *clock)
{
    memset(clock, 0, sizeof(CLOCK_t));
}