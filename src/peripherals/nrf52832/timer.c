#include "peripherals/nrf52832/timer.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct TIMER_inst_t
{
    size_t cc_num;

    uint32_t cc[TIMER_MAX_CC];
};

OPERATION(timer)
{
    TIMER_t *timer = (TIMER_t *)userdata;

    if (op == OP_RESET)
    {
        memset(timer->cc, 0, sizeof(timer->cc));
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    if (offset >= 0x540 && offset <= 0x554)
    {
        size_t cc_idx = (offset - 0x540) / 4;

        if (cc_idx < timer->cc_num)
            OP_RETURN_REG(timer->cc[cc_idx], WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

TIMER_t *timer_new(size_t cc_num)
{
    assert(cc_num <= TIMER_MAX_CC);

    TIMER_t *timer = (TIMER_t *)malloc(sizeof(TIMER_t));
    timer->cc_num = cc_num;

    return timer;
}
