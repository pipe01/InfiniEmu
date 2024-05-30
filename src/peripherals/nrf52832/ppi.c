#include "peripherals/nrf52832/ppi.h"
#include "peripherals/peripheral.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "cpu.h"

#define MAX_CHANNELS 32
#define MAX_SUBSCRIBERS 10

#define PERIPHERALS_COUNT 0x26
#define EVENTS_COUNT 64

_Thread_local PPI_t *current_ppi;

typedef struct
{
    bool enabled;
    uint32_t *event;
    uint32_t *task;
} channel_t;

typedef struct
{
    ppi_task_cb_t cb;
    void *userdata;

    uint64_t events;
} peripheral_t;

struct PPI_t
{
    cpu_t **cpu;

    peripheral_t *peripherals[PERIPHERALS_COUNT];
};

OPERATION(ppi)
{
    PPI_t *ppi = (PPI_t *)userdata;

    if (op == OP_RESET)
    {
        for (size_t i = 0; i < PERIPHERALS_COUNT; i++)
        {
            if (ppi->peripherals[i])
                ppi->peripherals[i]->events = 0;
        }

        return MEMREG_RESULT_OK;
    }

    // TODO: Implement

    return MEMREG_RESULT_OK;
}

PPI_t *ppi_new(cpu_t **cpu)
{
    PPI_t *ppi = calloc(1, sizeof(PPI_t));
    ppi->cpu = cpu;

    return ppi;
}

void ppi_add_peripheral(PPI_t *ppi, uint8_t id, ppi_task_cb_t cb, void *userdata)
{
    assert(id <= PERIPHERALS_COUNT - 1);

    peripheral_t *peripheral = ppi->peripherals[id];

    if (peripheral)
        abort();

    peripheral = malloc(sizeof(peripheral_t));
    peripheral->cb = cb;
    peripheral->userdata = userdata;

    ppi->peripherals[id] = peripheral;
}

void ppi_remove_peripheral(PPI_t *ppi, uint8_t id)
{
    assert(id < PERIPHERALS_COUNT);

    peripheral_t *peripheral = ppi->peripherals[id];

    if (peripheral)
    {
        free(peripheral);
        ppi->peripherals[id] = NULL;
    }
}

void ppi_fire_task(PPI_t *ppi, uint8_t peripheral_id, uint8_t task_id)
{
    assert(peripheral_id < PERIPHERALS_COUNT);

    peripheral_t *periph = ppi->peripherals[peripheral_id];
    assert(periph != NULL);

    periph->cb(ppi, peripheral_id, task_id, periph->userdata);
}

void ppi_fire_event(PPI_t *ppi, uint8_t peripheral_id, uint8_t event_id, bool pend_exception)
{
    assert(peripheral_id < PERIPHERALS_COUNT);
    assert(event_id < EVENTS_COUNT);

    peripheral_t *periph = ppi->peripherals[peripheral_id];
    assert(periph != NULL);

    periph->events |= (1 << event_id);

    if (pend_exception)
        cpu_exception_set_pending(*ppi->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(peripheral_id));

    // TODO: Implement channels
}

void ppi_clear_event(PPI_t *ppi, uint8_t peripheral_id, uint8_t event_id)
{
    assert(peripheral_id < PERIPHERALS_COUNT);
    assert(event_id < EVENTS_COUNT);

    peripheral_t *periph = ppi->peripherals[peripheral_id];

    if (periph)
        periph->events &= ~(1 << event_id);
}

bool ppi_event_is_set(PPI_t *ppi, uint8_t peripheral_id, uint8_t event_id)
{
    assert(peripheral_id < PERIPHERALS_COUNT);
    assert(event_id < EVENTS_COUNT);

    peripheral_t *periph = ppi->peripherals[peripheral_id];

    if (!periph)
        return false;

    return (periph->events & (1 << event_id)) != 0;
}
