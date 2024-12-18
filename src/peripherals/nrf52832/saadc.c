#include "peripherals/nrf52832/saadc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "memory.h"

struct SAADC_inst_t
{
    pins_t *pins;
};

OPERATION(saadc)
{
    SAADC_t *saadc = (SAADC_t *)userdata;

    if (op == OP_RESET)
    {
        pins_t *pins = saadc->pins;
        memset(saadc, 0, sizeof(SAADC_t));
        saadc->pins = pins;
        return MEMREG_RESULT_OK;
    }

    OP_IGNORE_LOAD_DATA
    OP_ASSERT_SIZE(op, WORD);

    // TODO: Implement

    return MEMREG_RESULT_OK;
}

NRF52_PERIPHERAL_CONSTRUCTOR(SAADC, saadc)
{
    SAADC_t *saadc = calloc(1, sizeof(SAADC_t));
    saadc->pins = ctx.pins;

    return saadc;
}
