#include "peripherals/nrf52832/ecb.h"

#include "peripherals/nrf52832/ppi.h"

enum
{
    TASKS_STARTECB = 0x000,  // Start ECB block encrypt
    TASKS_STOPECB = 0x004,   // Abort a possible executing ECB operation
    EVENTS_ENDECB = 0x100,   // ECB block encrypt complete
    EVENTS_ERRORECB = 0x104, // ECB block encrypt aborted because of a STOPECB task or due to an error
};

struct ECB_inst_t
{
    dma_t *dma;

    uint32_t ecbdataptr;
};

OPERATION(ecb)
{
    ECB_t *ecb = userdata;

    if (op == OP_RESET)
    {
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(TASKS_STARTECB)
        OP_TASK(TASKS_STOPECB)
        OP_EVENT(EVENTS_ENDECB)
        OP_EVENT(EVENTS_ERRORECB)

    case 0x504:
        OP_RETURN_REG(ecb->ecbdataptr, WORD);

    default:
        break;
    }

    return MEMREG_RESULT_OK;
}

PPI_TASK_HANDLER(ecb_task_handler)
{
    ECB_t *ecb = (ECB_t *)userdata;
    (void)ecb;

    switch (task)
    {
    case TASK_ID(TASKS_STARTECB):
    {
        uint8_t data[16];
        dma_read(ecb->dma, ecb->ecbdataptr, 16, data);

        abort();
        break;
    }

    default:
        break;
    }
}

NRF52_PERIPHERAL_CONSTRUCTOR(ECB, ecb)
{
    ECB_t *ecb = malloc(sizeof(ECB_t));
    ecb->dma = ctx.dma;

    ppi_add_peripheral(ctx.ppi, ctx.id, ecb_task_handler, ecb);

    return ecb;
}