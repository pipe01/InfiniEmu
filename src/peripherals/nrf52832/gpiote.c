#include "peripherals/nrf52832/gpiote.h"

#include <stdlib.h>
#include <string.h>

struct GPIOTE_inst_t
{
    uint32_t foo;
};

OPERATION(gpiote)
{
    GPIOTE_t *gpiote = (GPIOTE_t *)userdata;

    if (op == OP_RESET)
    {
        memset(gpiote, 0, sizeof(GPIOTE_t));
        return MEMREG_RESULT_OK;
    }

    // TODO: Implement

    return MEMREG_RESULT_OK;
}

NRF52_PERIPHERAL_CONSTRUCTOR(GPIOTE, gpiote)
{
    return (GPIOTE_t *)malloc(sizeof(GPIOTE_t));
}
