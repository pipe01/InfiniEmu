#include "peripherals/nrf52832/rtc.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "peripherals/nrf52832/ppi.h"

#define INT_TICK 0
#define INT_OVRFLW 1
#define INT_COMPARE0 16
#define INT_COMPARE1 17
#define INT_COMPARE2 18
#define INT_COMPARE3 19

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
    uint8_t id;
    size_t cc_num;

    uint32_t cc[RTC_MAX_CC];

    bool running;

    inten_t inten;
    uint32_t prescaler, counter, prescaler_counter;
};

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
        return MEMREG_RESULT_OK;
    }

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

    case 0x304: // INTENSET
        if (OP_IS_READ(op))
            *value = rtc->inten.value;
        else
            rtc->inten.value |= *value;
        return MEMREG_RESULT_OK;

    case 0x308: // INTENCLR
        if (OP_IS_READ(op))
            *value = rtc->inten.value;
        else
            rtc->inten.value &= ~*value;
        return MEMREG_RESULT_OK;

    case 0x340: // EVTEN
    case 0x344: // EVTENSET
    case 0x348: // EVTENCLR
        // TODO: Implement
        return MEMREG_RESULT_OK;

    case 0x504: // COUNTER
        OP_RETURN_REG(rtc->counter, WORD);

    case 0x508: // PRESCALER
        OP_RETURN_REG(rtc->prescaler, WORD);
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
        rtc->running = true;
        break;

    case TASK_ID(TASKS_STOP):
        rtc->running = false;
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

    ppi_add_peripheral(ctx.ppi, ctx.id, rtc_task_handler, rtc);

    return rtc;
}

void rtc_tick(RTC_t *rtc)
{
    if (!rtc->running)
        return;

    rtc->prescaler_counter++;

    if (rtc->prescaler_counter == rtc->prescaler)
    {
        rtc->prescaler_counter = 0;
        rtc->counter++;

        if (rtc->inten.TICK)
        {
            ppi_fire_event(current_ppi, rtc->id, EVENT_ID(EVENTS_TICK));
            cpu_exception_set_pending(*rtc->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(rtc->id));
        }

        if (rtc->counter == (1 << 24))
        {
            rtc->counter = 0;

            if (rtc->inten.OVRFLW)
            {
                ppi_fire_event(current_ppi, rtc->id, EVENT_ID(EVENTS_OVRFLW));
                cpu_exception_set_pending(*rtc->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(rtc->id));
            }
        }

        for (size_t i = 0; i < rtc->cc_num; i++)
        {
            if (rtc->counter == rtc->cc[i] && (rtc->inten.COMPARE & (1 << i)) != 0)
            {
                ppi_fire_event(current_ppi, rtc->id, EVENT_ID(EVENTS_COMPARE0) + i);
                cpu_exception_set_pending(*rtc->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(rtc->id));
            }
        }
    }
}