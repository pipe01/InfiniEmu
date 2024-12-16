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
    state_t *s;

    cpu_t **cpu;
    ticker_t *ticker;
    uint8_t id;
    size_t cc_num;
};

void rtc_tick(void *userdata)
{
    RTC_t *rtc = userdata;

    rtc->s->counter++;

    ppi_fire_event(current_ppi, rtc->id, EVENT_ID(RTC_EVENTS_TICK), rtc->s->inten.TICK);

    if (rtc->s->counter == (1 << 24))
    {
        rtc->s->counter = 0;

        ppi_fire_event(current_ppi, rtc->id, EVENT_ID(RTC_EVENTS_OVRFLW), rtc->s->inten.OVRFLW);
    }

    for (size_t i = 0; i < rtc->cc_num; i++)
    {
        if (rtc->s->counter == rtc->s->cc[i])
            ppi_fire_event(current_ppi, rtc->id, EVENT_ID(RTC_EVENTS_COMPARE0) + i, rtc->s->inten.COMPARE & (1 << i));
    }
}

OPERATION(rtc)
{
    state_t *state = ((RTC_t *)userdata)->s;

    if (op == OP_RESET)
    {
        memset(state, 0, sizeof(state_t));
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

        OP_INTENSET(state)
        OP_INTENCLR(state)

    case 0x340: // EVTEN
        OP_RETURN_REG(state->evten.value, WORD);

    case 0x344: // EVTENSET
        OP_RETURN_REG_SET(state->evten.value, WORD);

    case 0x348: // EVTENCLR
        OP_RETURN_REG_CLR(state->evten.value, WORD);

    case 0x504: // COUNTER
        OP_RETURN_REG(state->counter, WORD);

    case 0x508: // PRESCALER
        if (OP_IS_READ(op))
        {
            *value = state->prescaler;
        }
        else
        {
            if (state->running)
                fault_take(FAULT_RTC_INVALID_STATE);

            state->prescaler = *value;
        }

        return MEMREG_RESULT_OK;
    }

    if (offset >= 0x540 && offset <= 0x54C + 4)
    {
        uint32_t idx = (offset - 0x540) / 4;

        OP_RETURN_REG(state->cc[idx], WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

PPI_TASK_HANDLER(rtc_task_handler)
{
    RTC_t *rtc = (RTC_t *)userdata;

    switch (task)
    {
    case TASK_ID(RTC_TASKS_START):
        if (!rtc->s->running)
        {
            ticker_add(rtc->ticker, CLOCK_LFCLK, rtc_tick, rtc, rtc->s->prescaler + 1, true);

            rtc->s->running = true;
        }
        break;

    case TASK_ID(RTC_TASKS_STOP):
        if (rtc->s->running)
        {
            ticker_remove(rtc->ticker, CLOCK_LFCLK, rtc_tick);

            rtc->s->running = false;
        }
        break;

    case TASK_ID(RTC_TASKS_CLEAR):
        rtc->s->counter = 0;
        rtc->s->prescaler_counter = 0;
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
    rtc->s = state_store_alloc(ctx.state_store, PERIPHERAL_KEY(ctx.id), sizeof(state_t));

    ppi_add_peripheral(ctx.ppi, ctx.id, rtc_task_handler, rtc);

    return rtc;
}

uint32_t rtc_is_running(RTC_t *rtc)
{
    return rtc->s->running;
}

uint32_t rtc_get_counter(RTC_t *rtc)
{
    return rtc->s->counter;
}

double rtc_get_tick_interval_us(RTC_t *rtc)
{
    return ((double)(rtc->s->prescaler + 1) * 1e6) / 32768.0;
}
