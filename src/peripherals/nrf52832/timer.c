#include "peripherals/nrf52832/timer.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

enum
{
    TASKS_START = 0x000,
    TASKS_STOP = 0x004,
    TASKS_COUNT = 0x008,
    TASKS_CLEAR = 0x00C,
    TASKS_SHUTDOWN = 0x010,
    TASKS_CAPTURE0 = 0x040,
    TASKS_CAPTURE1 = 0x044,
    TASKS_CAPTURE2 = 0x048,
    TASKS_CAPTURE3 = 0x04C,
    TASKS_CAPTURE4 = 0x050,
    TASKS_CAPTURE5 = 0x054,
    EVENTS_COMPARE0 = 0x140,
    EVENTS_COMPARE1 = 0x144,
    EVENTS_COMPARE2 = 0x148,
    EVENTS_COMPARE3 = 0x14C,
    EVENTS_COMPARE4 = 0x150,
    EVENTS_COMPARE5 = 0x154,
};

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

struct TIMER_inst_t
{
    size_t cc_num;
    uint8_t id;

    bool running;

    uint32_t mode, bitmode;
    uint32_t prescaler;

    uint32_t counter;

    uint32_t cc[TIMER_MAX_CC];
};

OPERATION(timer)
{
    TIMER_t *timer = (TIMER_t *)userdata;

    if (op == OP_RESET)
    {
        *timer = (TIMER_t){
            .cc_num = timer->cc_num,
            .id = timer->id,
        };
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(TASKS_START)
        OP_TASK(TASKS_STOP)
        OP_TASK(TASKS_COUNT)
        OP_TASK(TASKS_CLEAR)
        OP_TASK(TASKS_SHUTDOWN)
        OP_TASK(TASKS_CAPTURE0)
        OP_TASK(TASKS_CAPTURE1)
        OP_TASK(TASKS_CAPTURE2)
        OP_TASK(TASKS_CAPTURE3)
        OP_TASK(TASKS_CAPTURE4)
        OP_TASK(TASKS_CAPTURE5)
        OP_EVENT(EVENTS_COMPARE0)
        OP_EVENT(EVENTS_COMPARE1)
        OP_EVENT(EVENTS_COMPARE2)
        OP_EVENT(EVENTS_COMPARE3)
        OP_EVENT(EVENTS_COMPARE4)
        OP_EVENT(EVENTS_COMPARE5)

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
    case TASK_ID(TASKS_START):
        timer->running = true;
        break;

    case TASK_ID(TASKS_STOP):
    case TASK_ID(TASKS_SHUTDOWN):
        timer->running = false;
        break;

    case TASK_ID(TASKS_COUNT):
        if (timer->mode == MODE_COUNTER)
            timer->counter++;
        break;

    case TASK_ID(TASKS_CLEAR):
        timer->counter = 0;
        break;

    case TASK_ID(TASKS_CAPTURE0):
        timer->cc[0] = timer->counter;
        break;

    case TASK_ID(TASKS_CAPTURE1):
        timer->cc[1] = timer->counter;
        break;

    case TASK_ID(TASKS_CAPTURE2):
        timer->cc[2] = timer->counter;
        break;

    case TASK_ID(TASKS_CAPTURE3):
        timer->cc[3] = timer->counter;
        break;

    case TASK_ID(TASKS_CAPTURE4):
        timer->cc[4] = timer->counter;
        break;

    case TASK_ID(TASKS_CAPTURE5):
        timer->cc[5] = timer->counter;
        break;
    }
}

TIMER_t *timer_new(uint8_t id, size_t cc_num)
{
    assert(cc_num <= TIMER_MAX_CC);

    TIMER_t *timer = (TIMER_t *)malloc(sizeof(TIMER_t));
    timer->cc_num = cc_num;
    timer->id = id;

    ppi_add_peripheral(current_ppi, id, timer_task_handler, timer);

    return timer;
}
