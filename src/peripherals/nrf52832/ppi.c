#include "peripherals/nrf52832/ppi.h"

#include <stdlib.h>

struct PPI_inst_t
{
    uint32_t foo;
};

OPERATION(ppi)
{
    // TODO: Implement

    return MEMREG_RESULT_OK;
}

PPI_t *ppi_new()
{
    return (PPI_t *)malloc(sizeof(PPI_t));
}
