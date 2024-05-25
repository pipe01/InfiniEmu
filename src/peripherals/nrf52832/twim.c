#include "peripherals/nrf52832/twim.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "peripherals/nrf52832/easydma.h"

struct TWIM_inst_t
{
    bus_i2c_t *i2c;
    uint8_t id;
    bool enabled;

    uint32_t address;

    easydma_reg_t tx, rx;
};

OPERATION(twim)
{
    TWIM_t *twim = (TWIM_t *)userdata;

    if (op == OP_RESET)
    {
        CLEAR_AFTER(TWIM_t, twim, enabled);
        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
        OP_TASK_RESULT(0x000, PPI_TASK_TWIM_STARTRX, MEMREG_RESULT_OK_CONTINUE)
        OP_TASK_RESULT(0x008, PPI_TASK_TWIM_STARTTX, MEMREG_RESULT_OK_CONTINUE)
        OP_TASK_RESULT(0x014, PPI_TASK_TWIM_STOP, MEMREG_RESULT_OK_CONTINUE)
        OP_TASK_RESULT(0x01C, PPI_TASK_TWIM_SUSPEND, MEMREG_RESULT_OK_CONTINUE)
        OP_TASK_RESULT(0x020, PPI_TASK_TWIM_RESUME, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(0x104, PPI_EVENT_TWIM_STOPPED, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(0x124, PPI_EVENT_TWIM_ERROR, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(0x148, PPI_EVENT_TWIM_SUSPENDED, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(0x14C, PPI_EVENT_TWIM_RXSTARTED, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(0x150, PPI_EVENT_TWIM_TXSTARTED, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(0x15C, PPI_EVENT_TWIM_LASTRX, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(0x160, PPI_EVENT_TWIM_LASTTX, MEMREG_RESULT_OK_CONTINUE)

    case 0x500: // ENABLE
        if (OP_IS_READ(op))
        {
            if (twim->enabled)
            {
                *value = TWIM_ENABLE_VALUE;
                return MEMREG_RESULT_OK;
            }
        }
        else if (*value == TWIM_ENABLE_VALUE)
        {
            twim->enabled = true;
            return MEMREG_RESULT_OK;
        }
        else if (*value == 0)
        {
            twim->enabled = false;
            return MEMREG_RESULT_OK_CONTINUE;
        }

        break;

        EASYDMA_CASES(twim)

    case 0x588: // ADDRESS
        OP_RETURN_REG_RESULT(twim->address, WORD, MEMREG_RESULT_OK_CONTINUE);
    }

    return MEMREG_RESULT_UNHANDLED;
}

TASK_HANDLER(twim, startrx)
{
    TWIM_t *twim = (TWIM_t *)userdata;

    if (twim->enabled)
    {
        size_t read = i2c_read(twim->i2c, twim->address, twim->rx.ptr, twim->rx.maxcnt);
        twim->rx.amount = read;

        ppi_fire_event(current_ppi, PPI_EVENT_TWIM_RXSTARTED);
        ppi_fire_event(current_ppi, PPI_EVENT_TWIM_LASTRX); // TODO: Delay LASTRX
    }
}

TASK_HANDLER(twim, starttx)
{
    TWIM_t *twim = (TWIM_t *)userdata;

    if (twim->enabled)
    {
        // TODO: Handle invalid I2C address
        i2c_write(twim->i2c, twim->address, twim->tx.ptr, twim->tx.maxcnt);

        ppi_fire_event(current_ppi, PPI_EVENT_TWIM_TXSTARTED);
        ppi_fire_event(current_ppi, PPI_EVENT_TWIM_LASTTX); // TODO: Delay LASTTX
    }
}

TASK_HANDLER_SHORT(twim, stop, TWIM_t, ppi_fire_event(current_ppi, PPI_EVENT_TWIM_STOPPED))
TASK_HANDLER_SHORT(twim, suspend, TWIM_t, ppi_fire_event(current_ppi, PPI_EVENT_TWIM_SUSPENDED))

TWIM_t *twim_new(uint8_t id, bus_i2c_t *i2c)
{
    TWIM_t *twim = (TWIM_t *)calloc(1, sizeof(TWIM_t));
    twim->i2c = i2c;
    twim->id = id;

    ppi_on_task(current_ppi, PPI_TASK_TWIM_STARTRX, twim_startrx_handler, twim);
    ppi_on_task(current_ppi, PPI_TASK_TWIM_STARTTX, twim_starttx_handler, twim);
    ppi_on_task(current_ppi, PPI_TASK_TWIM_STOP, twim_stop_handler, twim);
    ppi_on_task(current_ppi, PPI_TASK_TWIM_SUSPEND, twim_suspend_handler, twim);

    return twim;
}
