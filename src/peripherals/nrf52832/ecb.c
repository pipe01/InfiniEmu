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
    union
    {
        unsigned int ENDECB : 1;
        unsigned int ERRORECB : 1;
    };
    uint32_t value;
} inten_t;

typedef struct
{
    uint8_t key[16];
    uint8_t cleartext[16];
    uint8_t ciphertext[16];
} ecbdata_t;
static_assert(sizeof(ecbdata_t) == 48, "ecbdata_t size is not 48 bytes");

typedef struct
{
    uint32_t ecbdataptr;
    inten_t inten;
} state_t;

struct ECB_inst_t
{
    state_t;

    dma_t *dma;
};

OPERATION(ecb)
{
    ECB_t *ecb = userdata;

    if (op == OP_RESET)
    {
        memset(ecb, 0, sizeof(state_t));
        return MEMREG_RESULT_OK;
    }

    OP_IGNORE_LOAD_DATA
    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(TASKS_STARTECB)
        OP_TASK(TASKS_STOPECB)
        OP_EVENT(EVENTS_ENDECB)
        OP_EVENT(EVENTS_ERRORECB)

        OP_INTENSET(ecb)
        OP_INTENCLR(ecb)

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
        static_assert(sizeof(ecbdata.cleartext) == AES_BLOCKLEN, "ecbdata.cleartext size is not AES_BLOCKLEN bytes");

        dma_read(ecb->dma, ecb->ecbdataptr, sizeof(ecbdata_t), (uint8_t *)&ecbdata);

        uint8_t data[AES_BLOCKLEN];
        memcpy(data, ecbdata.cleartext, sizeof(data));

        struct AES_ctx ctx;
        AES_init_ctx(&ctx, ecbdata.key);
        AES_ECB_encrypt(&ctx, data);

        memcpy(ecbdata.ciphertext, data, sizeof(data));

        dma_write(ecb->dma, ecb->ecbdataptr, sizeof(ecbdata_t), (const uint8_t *)&ecbdata);

        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_ENDECB), ecb->inten.ENDECB);
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

    state_store_register(ctx.state_store, PERIPHERAL_KEY(ctx.id), ecb, sizeof(state_t));

    ppi_add_peripheral(ctx.ppi, ctx.id, ecb_task_handler, ecb);

    return ecb;
}