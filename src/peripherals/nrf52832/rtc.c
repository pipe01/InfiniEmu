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

struct RTC_inst_t
{
    size_t cc_num;
    uint32_t cc[RTC_MAX_CC];
    uint32_t event_cc[RTC_MAX_CC];

    bool started;

    uint32_t inten;
    uint32_t prescaler, counter, prescaler_counter;

    uint32_t event_tick, event_overflow;
};

OPERATION(rtc)
{
    RTC_t *rtc = (RTC_t *)userdata;

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
            *value = rtc->inten;
        else
            rtc->inten |= *value;
        return MEMREG_RESULT_OK;

    case 0x308: // INTENCLR
        if (OP_IS_READ(op))
            *value = rtc->inten;
        else
            rtc->inten &= ~*value;
        return MEMREG_RESULT_OK;

    case 0x340: // EVTEN
    case 0x344: // EVTENSET
    case 0x348: // EVTENCLR
        // TODO: Implement
        return MEMREG_RESULT_OK;

    case 0x508: // PRESCALER
        OP_RETURN_REG(rtc->prescaler, WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

RTC_t *rtc_new(size_t cc_num)
{
    assert(cc_num <= RTC_MAX_CC);

    RTC_t *rtc = (RTC_t *)malloc(sizeof(RTC_t));
    rtc->cc_num = cc_num;

    return rtc;
}

void rtc_reset(RTC_t *rtc)
{
    size_t cc_num = rtc->cc_num;

    memset(rtc, 0, sizeof(RTC_t));

    rtc->cc_num = cc_num;
}

void rtc_tick(RTC_t *rtc)
{
    rtc->prescaler_counter++;

    if (rtc->prescaler_counter == rtc->prescaler)
    {
        rtc->prescaler_counter = 0;
        rtc->counter++;

        if ((rtc->inten & (1 << INT_TICK)) != 0 && rtc->counter == 0)
        {
            rtc->event_tick = true;
            // TODO: Raise interrupt
        }

        if (rtc->counter == (1 << 24))
        {
            rtc->counter = 0;

            if ((rtc->inten & (1 << INT_OVRFLW)) != 0)
            {
                rtc->event_overflow = true;
                // TODO: Raise interrupt
            }
        }

        for (size_t i = 0; i < rtc->cc_num; i++)
        {
            if (rtc->counter == rtc->cc[i] && (rtc->inten & (1 << (INT_COMPARE0 + i))) != 0)
            {
                rtc->event_cc[i] = true;
                // TODO: Raise interrupt
            }
        }
    }
}