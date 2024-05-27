#include "peripherals/nrf52832/twim.h"

#include <stdlib.h>
#include <string.h>

#include "peripherals/nrf52832/easydma.h"

enum
{
    TASKS_STARTRX = 0x000,
    TASKS_STARTTX = 0x008,
    TASKS_STOP = 0x014,
    TASKS_SUSPEND = 0x01C,
    TASKS_RESUME = 0x020,
    EVENTS_STOPPED = 0x104,
    EVENTS_ERROR = 0x124,
    EVENTS_SUSPENDED = 0x148,
    EVENTS_RXSTARTED = 0x14C,
    EVENTS_TXSTARTED = 0x150,
    EVENTS_LASTRX = 0x15C,
    EVENTS_LASTTX = 0x160,
};

struct TWIM_inst_t
{
    uint8_t id;
    bus_i2c_t *i2c;
    bool enabled;

    uint32_t address;

    easydma_reg_t tx, rx;
};

PPI_TASK_HANDLER(twim_task_handler)
{
    TWIM_t *twim = (TWIM_t *)userdata;

    if (!twim->enabled)
        return;

    switch (task)
    {
    case TASK_ID(TASKS_STARTRX):
    {
        // TODO: Handle invalid I2C address
        size_t read = i2c_read(twim->i2c, twim->address, twim->rx.ptr, twim->rx.maxcnt);
        twim->rx.amount = read;

        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_RXSTARTED));
        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_LASTRX)); // TODO: Delay LASTRX
        break;
    }

    case TASK_ID(TASKS_STARTTX):
    {
        // TODO: Handle invalid I2C address
        i2c_write(twim->i2c, twim->address, twim->tx.ptr, twim->tx.maxcnt);

        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_TXSTARTED));
        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_LASTTX)); // TODO: Delay LASTTX
        break;
    }

    case TASK_ID(TASKS_STOP):
        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_STOPPED));
        break;

    case TASK_ID(TASKS_SUSPEND):
        ppi_fire_event(ppi, peripheral, EVENT_ID(EVENTS_SUSPENDED));
        break;
    }
}

OPERATION(twim)
{
    TWIM_t *twim = (TWIM_t *)userdata;

    if (op == OP_RESET)
    {
        *twim = (TWIM_t){
            .id = twim->id,
            .i2c = twim->i2c,
        };

        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
        OP_TASK_RESULT(TASKS_STARTRX, MEMREG_RESULT_OK_CONTINUE)
        OP_TASK_RESULT(TASKS_STARTTX, MEMREG_RESULT_OK_CONTINUE)
        OP_TASK_RESULT(TASKS_STOP, MEMREG_RESULT_OK_CONTINUE)
        OP_TASK_RESULT(TASKS_SUSPEND, MEMREG_RESULT_OK_CONTINUE)
        OP_TASK_RESULT(TASKS_RESUME, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(EVENTS_STOPPED, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(EVENTS_ERROR, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(EVENTS_SUSPENDED, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(EVENTS_RXSTARTED, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(EVENTS_TXSTARTED, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(EVENTS_LASTRX, MEMREG_RESULT_OK_CONTINUE)
        OP_EVENT_RESULT(EVENTS_LASTTX, MEMREG_RESULT_OK_CONTINUE)

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
            if (!twim->enabled)
                ppi_add_peripheral(current_ppi, twim->id, twim_task_handler, twim);

            twim->enabled = true;
            return MEMREG_RESULT_OK;
        }
        else if (*value == 0)
        {
            if (twim->enabled)
                ppi_remove_peripheral(current_ppi, twim->id);

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

TWIM_t *twim_new(uint8_t id, bus_i2c_t *i2c)
{
    TWIM_t *twim = (TWIM_t *)calloc(1, sizeof(TWIM_t));
    twim->i2c = i2c;
    twim->id = id;

    return twim;
}
