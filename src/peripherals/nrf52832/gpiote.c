#include "peripherals/nrf52832/gpiote.h"

#include <stdlib.h>
#include <string.h>

struct GPIOTE_inst_t
{
    uint32_t foo;
};

OPERATION(gpiote)
{
    // TODO: Implement

    return MEMREG_RESULT_OK;
}

GPIOTE_t *gpiote_new()
{
    return (GPIOTE_t *)malloc(sizeof(GPIOTE_t));
}

void gpiote_reset(GPIOTE_t *gpiote)
{
    memset(gpiote, 0, sizeof(GPIOTE_t));
}
