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
    OP_ASSERT_SIZE(op, WORD);

    DWT_t *dwt = (DWT_t *)userdata;

    switch (offset)
    {
    case 0x0: // CTRL
        OP_RETURN_REG(dwt->ctrl, WORD);

    case 0x4: // CYCCNT
        OP_RETURN_REG(dwt->cyccnt, WORD);
    }

    return false;
}

DWT_t *dwt_new()
{
    return (DWT_t *)malloc(sizeof(DWT_t));
}

void dwt_reset(DWT_t *dwt)
{
    dwt->ctrl = 0;
    dwt->cyccnt = 0;
}

void dwt_increment_cycle(DWT_t *dwt)
{
    if ((dwt->ctrl & (1 << DWT_CYCCNTENA)) != 0)
        dwt->cyccnt++;
}