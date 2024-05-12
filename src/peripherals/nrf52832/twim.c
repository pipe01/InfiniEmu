#include "peripherals/nrf52832/twim.h"

#include <stdlib.h>
#include <string.h>

#include "peripherals/nrf52832/easydma.h"

struct TWIM_inst_t
{
    bus_i2c_t *i2c;

    bool enabled;

    uint32_t address;

    easydma_reg_t tx, rx;

    uint32_t task_stop, task_resume;
    uint32_t event_stopped, event_error, event_suspended, event_rxstarted, event_txstarted, event_lastrx, event_lasttx;
};

OPERATION(twim)
{
    TWIM_t *twim = (TWIM_t *)userdata;

    if (op == OP_RESET)
    {
        bus_i2c_t *i2c = twim->i2c;
        memset(twim, 0, sizeof(TWIM_t));
        twim->i2c = i2c;
        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
    case 0x000: // TASKS_STARTRX
        if (OP_IS_READ(op))
        {
            *value = 0;
            return MEMREG_RESULT_OK_CONTINUE;
        }

        if (twim->enabled && *value)
        {
            size_t read = i2c_read(twim->i2c, twim->address, twim->rx.ptr, twim->rx.maxcnt);
            twim->rx.amount = read;
            twim->event_rxstarted = 1;
            twim->event_lastrx = 1;
            return MEMREG_RESULT_OK;
        }

        return MEMREG_RESULT_OK_CONTINUE;

    case 0x008: // TASKS_STARTTX
        if (OP_IS_READ(op))
        {
            *value = 0;
            return MEMREG_RESULT_OK_CONTINUE;
        }

        if (twim->enabled && *value)
        {
            // TODO: Handle invalid I2C address
            i2c_write(twim->i2c, twim->address, twim->tx.ptr, twim->tx.maxcnt);

            twim->event_txstarted = 1;
            twim->event_lasttx = 1;
            return MEMREG_RESULT_OK;
        }

        return MEMREG_RESULT_OK_CONTINUE;

    case 0x014: // TASKS_STOP
        if (OP_IS_READ(op))
        {
            *value = 0;
            return MEMREG_RESULT_OK_CONTINUE;
        }

        if (twim->enabled && *value)
        {
            twim->event_stopped = 1;
            return MEMREG_RESULT_OK;
        }

        return MEMREG_RESULT_OK_CONTINUE;

    case 0x01C: // TASKS_SUSPEND
        if (OP_IS_READ(op))
        {
            *value = 0;
            return MEMREG_RESULT_OK_CONTINUE;
        }

        if (twim->enabled && *value)
        {
            twim->event_suspended = 1;
            return MEMREG_RESULT_OK;
        }

        return MEMREG_RESULT_OK_CONTINUE;

    case 0x020: // TASKS_RESUME
        OP_RETURN_REG_RESULT(twim->task_resume, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x104: // EVENTS_STOPPED
        OP_RETURN_REG_RESULT(twim->event_stopped, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x124: // EVENTS_ERROR
        OP_RETURN_REG_RESULT(twim->event_error, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x148: // EVENTS_SUSPENDED
        OP_RETURN_REG_RESULT(twim->event_suspended, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x14C: // EVENTS_RXSTARTED
        OP_RETURN_REG_RESULT(twim->event_rxstarted, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x150: // EVENTS_TXSTARTED
        OP_RETURN_REG_RESULT(twim->event_txstarted, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x15C: // EVENTS_LASTRX
        OP_RETURN_REG_RESULT(twim->event_lastrx, WORD, MEMREG_RESULT_OK_CONTINUE);

    case 0x160: // EVENTS_LASTTX
        OP_RETURN_REG_RESULT(twim->event_lasttx, WORD, MEMREG_RESULT_OK_CONTINUE);

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

TWIM_t *twim_new(bus_i2c_t *i2c)
{
    TWIM_t *twim = (TWIM_t *)calloc(1, sizeof(TWIM_t));
    twim->i2c = i2c;
    return twim;
}
