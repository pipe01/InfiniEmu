#include "peripherals/nrf52832/spim.h"

#include <stdlib.h>
#include <string.h>

#include "peripherals/nrf52832/easydma.h"
#include "peripherals/nrf52832/ppi.h"

enum
{
    TASKS_START = 0x010,
    TASKS_STOP = 0x014,
    TASKS_SUSPEND = 0x01C,
    TASKS_RESUME = 0x020,
    EVENTS_STOPPED = 0x104,
    EVENTS_ENDRX = 0x110,
    EVENTS_END = 0x118,
    EVENTS_ENDTX = 0x120,
    EVENTS_STARTED = 0x14C,
};

typedef struct
{
    union
    {
        unsigned int ORDER : 1; // Bit order
        unsigned int CPHA : 1;  // Serial clock (SCK) phase
        unsigned int CPOL : 1;  // Serial clock (SCK) polarity
    };
    uint32_t value;
} config_t;

typedef union
{
    struct
    {
        unsigned int : 1;
        unsigned int STOPPED : 1;
        unsigned int : 2;
        unsigned int ENDRX : 1;
        unsigned int : 1;
        unsigned int END : 1;
        unsigned int : 1;
        unsigned int ENDTX : 1;
        unsigned int : 10;
        unsigned int STARTED : 1;
    };
    uint32_t value;
} inten_t;

struct SPIM_inst_t
{
    uint8_t id;
    bus_spi_t *bus;
    bool enabled;

    uint32_t psel_sck, psel_mosi, psel_miso;
    uint32_t frequency;

    easydma_reg_t tx, rx;

    config_t config;
    inten_t inten;
};

PPI_TASK_HANDLER(spim_task_handler)
{
    SPIM_t *spim = (SPIM_t *)userdata;

    assert(task == TASK_ID(TASKS_START));

    if (spim->tx.ptr)
    {
        spi_result_t result = spi_write(spim->bus, spim->tx.ptr, spim->tx.maxcnt);
        if (result == SPI_RESULT_OK)
            ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_ENDTX), spim->inten.ENDTX);
        else
            abort(); // TODO: Handle better
    }
    else if (spim->rx.ptr)
    {
        size_t read = spi_read(spim->bus, spim->rx.ptr, spim->rx.maxcnt);
        spim->rx.amount = read;
        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_ENDRX), spim->inten.ENDRX);
    }

    ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_END), spim->inten.END);
}

OPERATION(spim)
{
    SPIM_t *spim = (SPIM_t *)userdata;

    if (op == OP_RESET)
    {
        *spim = (SPIM_t){
            .id = spim->id,
            .bus = spim->bus,
        };
        ppi_remove_peripheral(current_ppi, spim->id);

        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
        OP_TASK(TASKS_START)
        OP_EVENT(EVENTS_STOPPED)
        OP_EVENT(EVENTS_ENDRX)
        OP_EVENT(EVENTS_END)
        OP_EVENT(EVENTS_ENDTX)
        OP_EVENT(EVENTS_STARTED)

    case 0x304: // INTENSET
        if (OP_IS_READ(op))
            *value = spim->inten.value;
        else
            spim->inten.value |= *value;
        return MEMREG_RESULT_OK_CONTINUE;

    case 0x308: // INTENCLR
        if (OP_IS_READ(op))
            *value = spim->inten.value;
        else
            spim->inten.value &= ~*value;
        return MEMREG_RESULT_OK_CONTINUE;

    case 0x500: // ENABLE
        if (OP_IS_READ(op))
        {
            if (spim->enabled)
            {
                *value = SPIM_ENABLE_VALUE;
                return MEMREG_RESULT_OK;
            }
            else
            {
                *value = 0;
                return MEMREG_RESULT_OK_CONTINUE;
            }
        }
        else if (*value == SPIM_ENABLE_VALUE)
        {
            if (!spim->enabled)
                ppi_add_peripheral(current_ppi, spim->id, spim_task_handler, spim);

            spim->enabled = true;
            return MEMREG_RESULT_OK;
        }
        else if (*value == 0)
        {
            if (spim->enabled)
                ppi_remove_peripheral(current_ppi, spim->id);

            spim->enabled = false;
            return MEMREG_RESULT_OK;
        }

        break;

    case 0x508: // PSEL.SCK
        OP_RETURN_REG_RESULT(spim->psel_sck, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x50C: // PSEL.MOSI
        OP_RETURN_REG_RESULT(spim->psel_mosi, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x510: // PSEL.MISO
        OP_RETURN_REG_RESULT(spim->psel_miso, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x524: // FREQUENCY
        OP_RETURN_REG_RESULT(spim->frequency, WORD, MEMREG_RESULT_OK_CONTINUE);

        EASYDMA_CASES(spim)

    case 0x554: // CONFIG
        OP_RETURN_REG_RESULT(spim->config.value, WORD, MEMREG_RESULT_OK_CONTINUE);
    }

    return MEMREG_RESULT_UNHANDLED;
}

NRF52_PERIPHERAL_CONSTRUCTOR(SPIM, spim)
{
    SPIM_t *spim = (SPIM_t *)malloc(sizeof(SPIM_t));
    spim->bus = ctx.spi;
    spim->id = ctx.id;

    return spim;
}
