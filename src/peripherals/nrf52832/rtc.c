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
        OP_TASK(0x000, PPI_TASK_RTC_START)
        OP_TASK(0x004, PPI_TASK_RTC_STOP)
        OP_TASK(0x008, PPI_TASK_RTC_CLEAR)
        OP_EVENT(0x100, PPI_EVENT_RTC_TICK)
        OP_EVENT(0x104, PPI_EVENT_RTC_OVRFLW)
        OP_EVENT(0x140, PPI_EVENT_RTC_COMPARE0)
        OP_EVENT(0x144, PPI_EVENT_RTC_COMPARE1)
        OP_EVENT(0x148, PPI_EVENT_RTC_COMPARE2)
        OP_EVENT(0x14C, PPI_EVENT_RTC_COMPARE3)

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

TASK_HANDLER_SHORT(rtc, start, RTC_t, p->running = true)
TASK_HANDLER_SHORT(rtc, stop, RTC_t, p->running = false)
TASK_HANDLER_SHORT(rtc, clear, RTC_t, p->counter = 0; p->prescaler_counter = 0)

RTC_t *rtc_new(size_t cc_num, cpu_t **cpu, uint32_t id)
{
    assert(cc_num <= RTC_MAX_CC);

    RTC_t *rtc = (RTC_t *)malloc(sizeof(RTC_t));
    rtc->cc_num = cc_num;
    rtc->cpu = cpu;
    rtc->id = id;

    ppi_on_task(current_ppi, PPI_TASK_RTC_START, rtc_start_handler, rtc);
    ppi_on_task(current_ppi, PPI_TASK_RTC_STOP, rtc_stop_handler, rtc);
    ppi_on_task(current_ppi, PPI_TASK_RTC_CLEAR, rtc_clear_handler, rtc);

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
            ppi_fire_event(current_ppi, PPI_EVENT_RTC_TICK);
            cpu_exception_set_pending(*rtc->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(rtc->id));
        }

        if (rtc->counter == (1 << 24))
        {
            rtc->counter = 0;

            if (rtc->inten.OVRFLW)
            {
                ppi_fire_event(current_ppi, PPI_EVENT_RTC_OVRFLW);
                cpu_exception_set_pending(*rtc->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(rtc->id));
            }
        }

        for (size_t i = 0; i < rtc->cc_num; i++)
        {
            if (rtc->counter == rtc->cc[i] && (rtc->inten.COMPARE & (1 << i)) != 0)
            {
                ppi_fire_event(current_ppi, PPI_EVENT_RTC_COMPARE0 + i);
                cpu_exception_set_pending(*rtc->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(rtc->id));
            }
        }
    }
}