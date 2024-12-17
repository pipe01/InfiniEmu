#include "peripherals/nrf52832/timer.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "fault.h"
#include "peripherals/nrf52832/ppi.h"

#define TICK_INTERVAL 1950

enum
{
    MODE_TIMER = 0,
    MODE_COUNTER = 1,
    MODE_LOW_POWER_COUNTER = 2,
};

enum
{
    BITMODE_16BIT = 0,
    BITMODE_8BIT = 1,
    BITMODE_24BIT = 2,
    BITMODE_32BIT = 3,
};

typedef struct
{
    bool running;

    uint32_t mode, bitmode;
    uint32_t prescaler;
    uint32_t inten;

    uint32_t counter, prescaler_counter;

    uint32_t cc[TIMER_MAX_CC];
} state_t;

struct TIMER_inst_t
{
    state_t;

    size_t cc_num;
    uint8_t id;
    ticker_t *ticker;
    cpu_t **cpu;
};

void timer_increase_counter(TIMER_t *timer)
{
    if (++timer->prescaler_counter < timer->prescaler)
        return;

    timer->prescaler_counter = 0;
    timer->counter++;

    uint32_t mask;

    switch (timer->bitmode)
    {
    case BITMODE_8BIT:
        mask = 0xFF;
        break;
    case BITMODE_16BIT:
        mask = 0xFFFF;
        break;
    case BITMODE_24BIT:
        mask = 0xFFFFFF;
        break;
    case BITMODE_32BIT:
        mask = 0xFFFFFFFF;
        break;
    default:
        fault_take(FAULT_NOT_IMPLEMENTED);
    }

    uint32_t counter = timer->counter & mask;

    for (size_t i = 0; i < timer->cc_num; i++)
    {
        if ((timer->cc[i] & mask) == counter)
        {
            ppi_fire_event(current_ppi, timer->id, EVENT_ID(TIMER_EVENTS_COMPARE0) + i, timer->inten & (1 << (i + 16)));
        }
    }
}

void timer_tick(void *userdata)
{
    TIMER_t *timer = userdata;

    timer_increase_counter(timer);
}

void timer_add_timer(TIMER_t *timer)
{
    ticker_add(timer->ticker, CLOCK_HFCLK, timer_tick, timer, TICK_INTERVAL, true);
}

OPERATION(timer)
{
    TIMER_t *timer = userdata;

    if (op == OP_RESET)
    {
        *timer = (TIMER_t){
            .cc_num = timer->cc_num,
            .id = timer->id,
            .ticker = timer->ticker,
            .cpu = timer->cpu,
        };
        return MEMREG_RESULT_OK;
    }
    if (op == OP_LOAD_DATA)
    {
        ticker_remove(timer->ticker, CLOCK_HFCLK, timer_tick);

        if (timer->running)
            timer_add_timer(timer);

        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(TIMER_TASKS_START)
        OP_TASK(TIMER_TASKS_STOP)
        OP_TASK(TIMER_TASKS_COUNT)
        OP_TASK(TIMER_TASKS_CLEAR)
        OP_TASK(TIMER_TASKS_SHUTDOWN)
        OP_TASK(TIMER_TASKS_CAPTURE0)
        OP_TASK(TIMER_TASKS_CAPTURE1)
        OP_TASK(TIMER_TASKS_CAPTURE2)
        OP_TASK(TIMER_TASKS_CAPTURE3)
        OP_TASK(TIMER_TASKS_CAPTURE4)
        OP_TASK(TIMER_TASKS_CAPTURE5)
        OP_EVENT(TIMER_EVENTS_COMPARE0)
        OP_EVENT(TIMER_EVENTS_COMPARE1)
        OP_EVENT(TIMER_EVENTS_COMPARE2)
        OP_EVENT(TIMER_EVENTS_COMPARE3)
        OP_EVENT(TIMER_EVENTS_COMPARE4)
        OP_EVENT(TIMER_EVENTS_COMPARE5)

    case 0x304: // INTENSET
        if (OP_IS_READ(op))
            *value = timer->inten;
        else
            timer->inten |= *value;
        return MEMREG_RESULT_OK;

    case 0x308: // INTENCLR
        if (OP_IS_READ(op))
            *value = timer->inten;
        else
            timer->inten &= ~(*value);
        return MEMREG_RESULT_OK;

    case 0x504: // MODE
        OP_RETURN_REG(timer->mode, WORD);

    case 0x508: // BITMODE
        OP_RETURN_REG(timer->bitmode, WORD);

    case 0x510: // PRESCALER
        OP_RETURN_REG(timer->prescaler, WORD);
    }

    if (offset >= 0x540 && offset <= 0x554)
    {
        size_t cc_idx = (offset - 0x540) / 4;

        if (cc_idx < timer->cc_num)
            OP_RETURN_REG(timer->cc[cc_idx], WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

PPI_TASK_HANDLER(timer_task_handler)
{
    TIMER_t *timer = (TIMER_t *)userdata;

    switch (task)
    {
    case TASK_ID(TIMER_TASKS_START):
        if (timer->mode == MODE_TIMER)
        {
            if (!timer->running)
                timer_add_timer(timer);

            timer->running = true;
        }
        break;

    case TASK_ID(TIMER_TASKS_STOP):
    case TASK_ID(TIMER_TASKS_SHUTDOWN):
        if (timer->running)
            ticker_remove(timer->ticker, CLOCK_HFCLK, timer_tick);

        timer->running = false;
        break;

    case TASK_ID(TIMER_TASKS_COUNT):
        if (timer->mode == MODE_COUNTER)
            timer->counter++;
        break;

    case TASK_ID(TIMER_TASKS_CLEAR):
        timer->counter = 0;
        break;

    case TASK_ID(TIMER_TASKS_CAPTURE0):
        timer->cc[0] = timer->counter;
        break;

    case TASK_ID(TIMER_TASKS_CAPTURE1):
        timer->cc[1] = timer->counter;
        break;

    case TASK_ID(TIMER_TASKS_CAPTURE2):
        timer->cc[2] = timer->counter;
        break;

    case TASK_ID(TIMER_TASKS_CAPTURE3):
        timer->cc[3] = timer->counter;
        break;

    case TASK_ID(TIMER_TASKS_CAPTURE4):
        timer->cc[4] = timer->counter;
        break;

    case TASK_ID(TIMER_TASKS_CAPTURE5):
        timer->cc[5] = timer->counter;
        break;
    }
}

NRF52_PERIPHERAL_CONSTRUCTOR(TIMER, timer, size_t cc_num)
{
    assert(cc_num <= TIMER_MAX_CC);

    TIMER_t *timer = malloc(sizeof(TIMER_t));
    timer->cc_num = cc_num;
    timer->id = ctx.id;
    timer->ticker = ctx.ticker;
    timer->cpu = ctx.cpu;

    state_store_register(ctx.state_store, PERIPHERAL_KEY(ctx.id), timer, sizeof(state_t));

    ppi_add_peripheral(ctx.ppi, ctx.id, timer_task_handler, timer);

    return timer;
}
