#include "peripherals/nrf52832/ecb.h"

#include <string.h>

#include "peripherals/nrf52832/ppi.h"

#define CBC 0
#define CTR 0
#include "tiny-AES-c/aes.h"

enum
{
    TASKS_STARTECB = 0x000,  // Start ECB block encrypt
    TASKS_STOPECB = 0x004,   // Abort a possible executing ECB operation
    EVENTS_ENDECB = 0x100,   // ECB block encrypt complete
    EVENTS_ERRORECB = 0x104, // ECB block encrypt aborted because of a STOPECB task or due to an error
};

typedef struct
{
    uint8_t key[16];
    uint8_t cleartext[16];
    uint8_t ciphertext[16];
} ecbdata_t;
static_assert(sizeof(ecbdata_t) == 48, "ecbdata_t size is not 48 bytes");

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

    switch (task)
    {
    case TASK_ID(TASKS_STARTECB):
    {
        ecbdata_t ecbdata;
        static_assert(sizeof(ecbdata.cleartext) == AES_BLOCKLEN);

        dma_read(ecb->dma, ecb->ecbdataptr, sizeof(ecbdata_t), (uint8_t *)&ecbdata);

        uint8_t data[AES_BLOCKLEN];
        memcpy(data, ecbdata.cleartext, sizeof(data));

        struct AES_ctx ctx;
        AES_init_ctx(&ctx, ecbdata.key);
        AES_ECB_encrypt(&ctx, data);

        memcpy(ecbdata.ciphertext, data, sizeof(data));

        dma_write(ecb->dma, ecb->ecbdataptr, sizeof(ecbdata_t), (const uint8_t *)&ecbdata);

        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_ENDECB));
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