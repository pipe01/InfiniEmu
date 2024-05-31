#include "peripherals/nrf52832/rtc.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "peripherals/nrf52832/ppi.h"

#define TICK_INTERVAL 50

typedef union
{
    struct
    {
        unsigned int TICK : 1;
        unsigned int OVRFLW : 1;
        unsigned int : 14;
        unsigned int COMPARE : 4;
    };
    uint32_t value;
} inten_t;

static_assert(sizeof(inten_t) == 4);

enum
{
    TASKS_START = 0x000,
    TASKS_STOP = 0x004,
    TASKS_CLEAR = 0x008,
    TASKS_TRIGOVRFLW = 0x00C,
    EVENTS_TICK = 0x100,
    EVENTS_OVRFLW = 0x104,
    EVENTS_COMPARE0 = 0x140,
    EVENTS_COMPARE1 = 0x144,
    EVENTS_COMPARE2 = 0x148,
    EVENTS_COMPARE3 = 0x14C,
};

struct RTC_inst_t
{
    cpu_t **cpu;
    ticker_t *ticker;
    uint8_t id;
    size_t cc_num;

    uint32_t cc[RTC_MAX_CC];

    bool running;

    size_t tick_interval_us;
    size_t last_check_us;
    struct timeval timeval;

    inten_t inten, evten;
    uint32_t prescaler, counter, prescaler_counter;
};

void rtc_tick(void *userdata)
{
    RTC_t *rtc = userdata;

    gettimeofday(&rtc->timeval, NULL);
    size_t now = rtc->timeval.tv_sec * 1e6 + rtc->timeval.tv_usec;

    size_t elapsed = now - rtc->last_check_us;
    size_t elapsed_ticks = elapsed / rtc->tick_interval_us;

    if (elapsed_ticks > 0)
    {
        rtc->last_check_us = now;

        // if (elapsed_ticks > 1)
        //     printf("Warning: skipped %ld ticks\n", elapsed_ticks - 1);

        rtc->counter++;

        ppi_fire_event(current_ppi, rtc->id, EVENT_ID(EVENTS_TICK), rtc->inten.TICK);

        if (rtc->counter == (1 << 24))
        {
            rtc->counter = 0;

            ppi_fire_event(current_ppi, rtc->id, EVENT_ID(EVENTS_OVRFLW), rtc->inten.OVRFLW);
        }

        for (size_t i = 0; i < rtc->cc_num; i++)
        {
            if (rtc->counter == rtc->cc[i])
                ppi_fire_event(current_ppi, rtc->id, EVENT_ID(EVENTS_COMPARE0) + i, rtc->inten.COMPARE & (1 << i));
        }
    }
}

OPERATION(rtc)
{
    RTC_t *rtc = (RTC_t *)userdata;

    if (op == OP_RESET)
    {
        rtc->running = false;
        memset(rtc->cc, 0, sizeof(rtc->cc));
        rtc->inten.value = 0;
        rtc->prescaler = 0;
        rtc->counter = 0;
        rtc->prescaler_counter = 0;
        rtc->tick_interval_us = 0;
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(TASKS_START)
        OP_TASK(TASKS_STOP)
        OP_TASK(TASKS_CLEAR)
        OP_EVENT(EVENTS_TICK)
        OP_EVENT(EVENTS_OVRFLW)
        OP_EVENT(EVENTS_COMPARE0)
        OP_EVENT(EVENTS_COMPARE1)
        OP_EVENT(EVENTS_COMPARE2)
        OP_EVENT(EVENTS_COMPARE3)

        OP_INTENSET(rtc)
        OP_INTENCLR(rtc)

    case 0x340: // EVTEN
        OP_RETURN_REG(rtc->evten.value, WORD);

    case 0x344: // EVTENSET
        OP_RETURN_REG_SET(rtc->evten.value, WORD);

    case 0x348: // EVTENCLR
        OP_RETURN_REG_CLR(rtc->evten.value, WORD);

    case 0x504: // COUNTER
        OP_RETURN_REG(rtc->counter, WORD);

    case 0x508: // PRESCALER
        if (OP_IS_READ(op))
        {
            *value = rtc->prescaler;
        }
        else
        {
            rtc->prescaler = *value;
            rtc->tick_interval_us = ((size_t)(rtc->prescaler + 1) * 1e6) / 32768;
        }

        return MEMREG_RESULT_OK;
    }

    if (offset >= 0x540 && offset <= 0x54C + 4)
    {
        uint32_t idx = (offset - 0x540) / 4;

        OP_RETURN_REG(rtc->cc[idx], WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

PPI_TASK_HANDLER(rtc_task_handler)
{
    RTC_t *rtc = (RTC_t *)userdata;

    switch (task)
    {
    case TASK_ID(TASKS_START):
        if (!rtc->running)
        {
            ticker_add(rtc->ticker, rtc_tick, rtc, TICK_INTERVAL);

            gettimeofday(&rtc->timeval, NULL);
            rtc->last_check_us = rtc->timeval.tv_sec * 1e6 + rtc->timeval.tv_usec;

            rtc->running = true;
        }
        break;

    case TASK_ID(TASKS_STOP):
        if (rtc->running)
        {
            ticker_remove(rtc->ticker, rtc_tick);

            rtc->running = false;
        }
        break;

    case TASK_ID(TASKS_CLEAR):
        rtc->counter = 0;
        rtc->prescaler_counter = 0;
        break;
    }
}

NRF52_PERIPHERAL_CONSTRUCTOR(RTC, rtc, size_t cc_num)
{
    assert(cc_num <= RTC_MAX_CC);

    RTC_t *rtc = (RTC_t *)malloc(sizeof(RTC_t));
    rtc->cc_num = cc_num;
    rtc->cpu = ctx.cpu;
    rtc->id = ctx.id;
    rtc->ticker = ctx.ticker;

    ppi_add_peripheral(ctx.ppi, ctx.id, rtc_task_handler, rtc);

    return rtc;
}
