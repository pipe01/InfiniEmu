#include "peripherals/nrf52832/ppi.h"
#include "peripherals/peripheral.h"

#include <stdlib.h>
#include <string.h>

#define MAX_CHANNELS 32
#define MAX_SUBSCRIBERS 10

_Thread_local PPI_t *current_ppi;

typedef struct
{
    bool enabled;
    uint32_t *event;
    uint32_t *task;
} channel_t;

typedef struct
{
    bool is_fired;
} event_t;

typedef struct
{
    ppi_task_cb_t cb;
    void *userdata;
} task_t;

struct PPI_t
{
    task_t tasks[PPI_TASKS_COUNT];
    event_t events[PPI_EVENTS_COUNT];
};

OPERATION(ppi)
{
    PPI_t *ppi = (PPI_t *)userdata;

    if (op == OP_RESET)
    {
        memset(ppi->events, 0, sizeof(ppi->events));
        return MEMREG_RESULT_OK;
    }

    // TODO: Implement

    return MEMREG_RESULT_OK;
}

PPI_t *ppi_new()
{
    return (PPI_t *)calloc(1, sizeof(PPI_t));
}

void ppi_fire_task(PPI_t *ppi, ppi_tasks_t task)
{
    task_t *task_inst = &ppi->tasks[task];

    if (task_inst->cb)
        task_inst->cb(task, task_inst->userdata);
}

void ppi_on_task(PPI_t *ppi, ppi_tasks_t task, ppi_task_cb_t cb, void *userdata)
{
    task_t *task_inst = &ppi->tasks[task];

    if (task_inst->cb)
        abort();

    task_inst->cb = cb;
    task_inst->userdata = userdata;
}

void ppi_fire_event(PPI_t *ppi, ppi_events_t event)
{
    ppi->events[event].is_fired = true;

    // TODO: Implement
}

void ppi_clear_event(PPI_t *ppi, ppi_events_t event)
{
    ppi->events[event].is_fired = false;
}

bool ppi_event_is_set(PPI_t *ppi, ppi_events_t event)
{
    return ppi->events[event].is_fired;
}
