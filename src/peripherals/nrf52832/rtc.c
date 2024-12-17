#include "peripherals/nrf52832/rtc.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "fault.h"
#include "ie_time.h"
#include "peripherals/nrf52832/ppi.h"

#define TICK_INTERVAL 100

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

static_assert(sizeof(inten_t) == 4, "inten_t size is incorrect");

typedef struct
{
    uint32_t cc[RTC_MAX_CC];

    bool running;

    inten_t inten, evten;
    uint32_t prescaler, counter, prescaler_counter;
} state_t;

struct RTC_inst_t
{
    state_t;

    cpu_t **cpu;
    ticker_t *ticker;
    uint8_t id;
    size_t cc_num;
};

void rtc_tick(void *userdata)
{
    RTC_t *rtc = userdata;

    rtc->counter++;

    ppi_fire_event(current_ppi, rtc->id, EVENT_ID(RTC_EVENTS_TICK), rtc->inten.TICK);

    if (rtc->counter == (1 << 24))
    {
        rtc->counter = 0;

        ppi_fire_event(current_ppi, rtc->id, EVENT_ID(RTC_EVENTS_OVRFLW), rtc->inten.OVRFLW);
    }

    for (size_t i = 0; i < rtc->cc_num; i++)
    {
        if (rtc->counter == rtc->cc[i])
            ppi_fire_event(current_ppi, rtc->id, EVENT_ID(RTC_EVENTS_COMPARE0) + i, rtc->inten.COMPARE & (1 << i));
    }
}

OPERATION(rtc)
{
    state_t *rtc = userdata;

    if (op == OP_RESET)
    {
        memset(rtc, 0, sizeof(state_t));
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(RTC_TASKS_START)
        OP_TASK(RTC_TASKS_STOP)
        OP_TASK(RTC_TASKS_CLEAR)
        OP_EVENT(RTC_EVENTS_TICK)
        OP_EVENT(RTC_EVENTS_OVRFLW)
        OP_EVENT(RTC_EVENTS_COMPARE0)
        OP_EVENT(RTC_EVENTS_COMPARE1)
        OP_EVENT(RTC_EVENTS_COMPARE2)
        OP_EVENT(RTC_EVENTS_COMPARE3)

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
            if (rtc->running)
                fault_take(FAULT_RTC_INVALID_STATE);

            rtc->prescaler = *value;
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
    RTC_t *rtc = userdata;

    switch (task)
    {
    case TASK_ID(RTC_TASKS_START):
        if (!rtc->running)
        {
            ticker_add(rtc->ticker, CLOCK_LFCLK, rtc_tick, rtc, rtc->prescaler + 1, true);

            rtc->running = true;
        }
        break;

    case TASK_ID(RTC_TASKS_STOP):
        if (rtc->running)
        {
            ticker_remove(rtc->ticker, CLOCK_LFCLK, rtc_tick);

            rtc->running = false;
        }
        break;

    case TASK_ID(RTC_TASKS_CLEAR):
        rtc->counter = 0;
        rtc->prescaler_counter = 0;
        break;
    }
}

NRF52_PERIPHERAL_CONSTRUCTOR(RTC, rtc, size_t cc_num)
{
    assert(cc_num <= RTC_MAX_CC);

    RTC_t *rtc = malloc(sizeof(RTC_t));
    rtc->cc_num = cc_num;
    rtc->cpu = ctx.cpu;
    rtc->id = ctx.id;
    rtc->ticker = ctx.ticker;

    state_store_register(ctx.state_store, PERIPHERAL_KEY(ctx.id), rtc, sizeof(state_t));

    ppi_add_peripheral(ctx.ppi, ctx.id, rtc_task_handler, rtc);

    return rtc;
}

uint32_t rtc_is_running(RTC_t *rtc)
{
    return rtc->running;
}

uint32_t rtc_get_counter(RTC_t *rtc)
{
    return rtc->counter;
}

double rtc_get_tick_interval_us(RTC_t *rtc)
{
    return ((double)(rtc->prescaler + 1) * 1e6) / 32768.0;
}
