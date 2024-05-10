#include "peripherals/nrf52832/spim.h"

#include <stdlib.h>
#include <string.h>

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

typedef struct
{
    union
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
    bool enabled;

    uint32_t psel_sck, psel_mosi, psel_miso;
    uint32_t frequency;

    uint32_t event_stopped, event_endrx, event_end, event_endtx, event_started;

    config_t config;
    inten_t inten;
};

OPERATION(spim)
{
    SPIM_t *spim = (SPIM_t *)userdata;

    if (op == OP_RESET)
    {
        memset(spim, 0, sizeof(SPIM_t));
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    if (spim->enabled)
    {
        switch (offset)
        {

        default:
            return MEMREG_RESULT_UNHANDLED;
        }
    }

    switch (offset)
    {
    case 0x104: // EVENTS_STOPPED
        OP_RETURN_REG_RESULT(spim->event_stopped, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x110: // EVENTS_ENDRX
        OP_RETURN_REG_RESULT(spim->event_endrx, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x118: // EVENTS_END
        OP_RETURN_REG_RESULT(spim->event_end, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x120: // EVENTS_ENDTX
        OP_RETURN_REG_RESULT(spim->event_endtx, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x14C: // EVENTS_STARTED
        OP_RETURN_REG_RESULT(spim->event_started, WORD, MEMREG_RESULT_OK_CONTINUE);

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
        }
        else if (*value == SPIM_ENABLE_VALUE)
        {
            spim->enabled = true;
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

    case 0x554: // CONFIG
        OP_RETURN_REG_RESULT(spim->config.value, WORD, MEMREG_RESULT_OK_CONTINUE);
    }

    return MEMREG_RESULT_UNHANDLED;
}

SPIM_t *spim_new()
{
    return (SPIM_t *)malloc(sizeof(SPIM_t));
}
