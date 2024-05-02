#include <stdlib.h>

#include "peripherals/nrf52832/radio.h"

struct RADIO_inst_t
{
    uint32_t foo;
};

OPERATION(radio)
{
    if (op == OP_RESET)
    {
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    // RADIO_t *radio = (RADIO_t *)userdata;

    switch (offset)
    {
        case 0x73C: // Undocumented
            *value = 0x00003090;
            return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

RADIO_t *radio_new()
{
    return (RADIO_t *)malloc(sizeof(RADIO_t));
}
