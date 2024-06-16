#include "peripherals/nrf52832/spi.h"

#include "fault.h"
#include "peripherals/nrf52832/ppi.h"

enum
{
    EVENTS_READY = 0x108,
};

#define READ_BUFFER_SIZE 50

struct SPI_inst_t
{
    uint8_t id;
    bus_spi_t *bus;
    bool enabled;
};

PPI_TASK_HANDLER(spi_task_handler)
{
}

OPERATION(spi)
{
    SPI_t *spi = userdata;

    if (op == OP_RESET)
    {
        spi->enabled = false;
        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
        OP_EVENT(EVENTS_READY)

    case 0x500: // ENABLE
        if (OP_IS_READ(op))
        {
            if (spi->enabled)
            {
                *value = SPI_ENABLE_VALUE;
                return MEMREG_RESULT_OK;
            }
            else
            {
                *value = 0;
                return MEMREG_RESULT_OK_CONTINUE;
            }
        }
        else if (*value == SPI_ENABLE_VALUE)
        {
            if (!spi->enabled)
                ppi_add_peripheral(current_ppi, spi->id, spi_task_handler, spi);

            spi->enabled = true;
            return MEMREG_RESULT_OK;
        }
        else
        {
            if (spi->enabled)
                ppi_remove_peripheral(current_ppi, spi->id);

            spi->enabled = false;
            return MEMREG_RESULT_OK_CONTINUE;
        }
        break;

    case 0x518: // RXD
        if (spi->enabled)
        {
            OP_ASSERT_READ(op);

            uint8_t byte;
            bus_spi_read(spi->bus, &byte);
            *value = byte;

            printf("SPI RXD 0x%02X\n", byte);

            // ppi_fire_event(current_ppi, spi->id, EVENT_ID(EVENTS_READY), false); // TODO: Should we fire this event here?
            return MEMREG_RESULT_OK;
        }
        break;

    case 0x51C: // TXD
        if (spi->enabled)
        {
            OP_ASSERT_WRITE(op);

            printf("SPI TXD: %02X\n", *value);

            spi_result_t result = bus_spi_write(spi->bus, *value);
            if (result != SPI_RESULT_OK)
                fault_take(FAULT_NOT_IMPLEMENTED); // TODO: Handle better

            ppi_fire_event(current_ppi, spi->id, EVENT_ID(EVENTS_READY), false);

            return MEMREG_RESULT_OK;
        }
        break;

    default:
        break;
    }

    return MEMREG_RESULT_UNHANDLED;
}

NRF52_PERIPHERAL_CONSTRUCTOR(SPI, spi)
{
    SPI_t *spi = malloc(sizeof(SPI_t));
    spi->bus = ctx.spi;
    spi->id = ctx.id;
    spi->enabled = false;

    return spi;
}
