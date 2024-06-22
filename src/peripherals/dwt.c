#include "peripherals/dwt.h"

#include <stdlib.h>

#include "memory.h"

struct DWT_inst_t
{
    uint32_t ctrl;
    uint32_t cyccnt;
};

OPERATION(dwt)
{
    DWT_t *dwt = (DWT_t *)userdata;

    if (op == OP_RESET)
    {
        dwt->ctrl = 0x40000001;
        dwt->cyccnt = 0;
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
    case 0x0: // CTRL
        OP_RETURN_REG(dwt->ctrl, WORD);

    case 0x4: // CYCCNT
        OP_RETURN_REG(dwt->cyccnt, WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

DWT_t *dwt_new()
{
    return malloc(sizeof(DWT_t));
}

void dwt_increment_cycle(DWT_t *dwt)
{
    if ((dwt->ctrl & (1 << DWT_CYCCNTENA)) != 0)
        dwt->cyccnt++;
}