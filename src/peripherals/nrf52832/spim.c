#include "peripherals/nrf52832/spim.h"

#include <stdlib.h>
#include <string.h>

struct SPIM_inst_t
{
    bool enabled;

    uint32_t psel_sck, psel_mosi, psel_miso;
    uint32_t frequency;
};

OPERATION(spim)
{
    OP_ASSERT_SIZE(op, WORD);

    SPIM_t *spim = (SPIM_t *)userdata;

    switch (offset)
    {
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
    }

    return MEMREG_RESULT_UNHANDLED;
}

SPIM_t *spim_new()
{
    return (SPIM_t *)malloc(sizeof(SPIM_t));
}

void spim_reset(SPIM_t *spim)
{
    memset(spim, 0, sizeof(SPIM_t));
}
