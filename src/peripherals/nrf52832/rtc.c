#include "peripherals/nrf52832/rtc.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

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

struct RTC_inst_t
{
    cpu_t **cpu;
    uint32_t id;
    size_t cc_num;

    uint32_t cc[RTC_MAX_CC];
    uint32_t event_cc[RTC_MAX_CC];

    bool started;

    inten_t inten;
    uint32_t prescaler, counter, prescaler_counter;

    uint32_t event_tick, event_overflow;
};

OPERATION(rtc)
{
    RTC_t *rtc = (RTC_t *)userdata;

    if (op == OP_RESET)
    {
        rtc->started = false;
        memset(rtc->cc, 0, sizeof(rtc->cc));
        memset(rtc->event_cc, 0, sizeof(rtc->event_cc));
        rtc->inten.value = 0;
        rtc->prescaler = 0;
        rtc->counter = 0;
        rtc->prescaler_counter = 0;
        rtc->event_tick = 0;
        rtc->event_overflow = 0;
        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
    case 0x000: // TASKS_START
        OP_ASSERT_WRITE(op);

        if (*value)
            rtc->started = true;
        return MEMREG_RESULT_OK;

    case 0x004: // TASKS_STOP
        OP_ASSERT_WRITE(op);

        if (*value)
            rtc->started = false;
        return MEMREG_RESULT_OK;

    case 0x008: // TASKS_CLEAR
        OP_ASSERT_WRITE(op);

        if (*value)
        {
            rtc->counter = 0;
            rtc->prescaler_counter = 0;
        }
        return MEMREG_RESULT_OK;

    case 0x100: // EVENTS_TICK
        OP_RETURN_REG(rtc->event_tick, WORD);

    case 0x104: // EVENTS_OVRFLW
        OP_RETURN_REG(rtc->event_overflow, WORD);

    case 0x140: // EVENTS_COMPARE[0]
        OP_RETURN_REG(rtc->event_cc[0], WORD);

    case 0x144: // EVENTS_COMPARE[1]
        OP_RETURN_REG(rtc->event_cc[1], WORD);

    case 0x148: // EVENTS_COMPARE[2]
        OP_RETURN_REG(rtc->event_cc[2], WORD);

    case 0x14C: // EVENTS_COMPARE[3]
        OP_RETURN_REG(rtc->event_cc[3], WORD);

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

RTC_t *rtc_new(size_t cc_num, cpu_t **cpu, uint32_t id)
{
    assert(cc_num <= RTC_MAX_CC);

    RTC_t *rtc = (RTC_t *)malloc(sizeof(RTC_t));
    rtc->cc_num = cc_num;
    rtc->cpu = cpu;
    rtc->id = id;

    return rtc;
}

void rtc_tick(RTC_t *rtc)
{
    if (!rtc->started)
        return;

    rtc->prescaler_counter++;

    if (rtc->prescaler_counter == rtc->prescaler)
    {
        rtc->prescaler_counter = 0;
        rtc->counter++;

        if (rtc->inten.TICK)
        {
            rtc->event_tick = true;
            cpu_exception_set_pending(*rtc->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(rtc->id));
        }

        if (rtc->counter == (1 << 24))
        {
            rtc->counter = 0;

            if (rtc->inten.OVRFLW)
            {
                rtc->event_overflow = true;
                cpu_exception_set_pending(*rtc->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(rtc->id));
            }
        }

        for (size_t i = 0; i < rtc->cc_num; i++)
        {
            if (rtc->counter == rtc->cc[i] && (rtc->inten.COMPARE & (1 << i)) != 0)
            {
                rtc->event_cc[i] = true;
                cpu_exception_set_pending(*rtc->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(rtc->id));
            }
        }
    }
}