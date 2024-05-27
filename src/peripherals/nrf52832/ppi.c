#include "peripherals/nrf52832/ppi.h"
#include "peripherals/peripheral.h"

#include <stdlib.h>
#include <string.h>

#define MAX_CHANNELS 32
#define MAX_SUBSCRIBERS 10

#define TASKS_COUNT ((1 << 16) - 1)
#define EVENTS_COUNT ((1 << 16) - 1)

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
    task_t *tasks[TASKS_COUNT];
    event_t *events[EVENTS_COUNT];
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

void ppi_fire_task(PPI_t *ppi, uint16_t task_id)
{
    task_t *task_inst = ppi->tasks[task_id];

    if (task_inst)
        task_inst->cb(task_id, task_inst->userdata);
    else
        abort();
}

void ppi_on_task(PPI_t *ppi, uint16_t task_id, ppi_task_cb_t cb, void *userdata)
{
    task_t **task_inst = &ppi->tasks[task_id];

    if (task_inst)
        abort();

    *task_inst = malloc(sizeof(task_t));
    (*task_inst)->cb = cb;
    (*task_inst)->userdata = userdata;
}

static void ppi_ensure_event(PPI_t *ppi, uint16_t event_id)
{
    if (!ppi->events[event_id])
        ppi->events[event_id] = calloc(1, sizeof(event_t));
}

void ppi_fire_event(PPI_t *ppi, uint16_t event_id)
{
    ppi_ensure_event(ppi, event_id);

    ppi->events[event_id]->is_fired = true;

    // TODO: Implement
}

void ppi_clear_event(PPI_t *ppi, uint16_t event_id)
{
    ppi_ensure_event(ppi, event_id);

    ppi->events[event_id]->is_fired = false;
}

bool ppi_event_is_set(PPI_t *ppi, uint16_t event_id)
{
    ppi_ensure_event(ppi, event_id);

    return ppi->events[event_id]->is_fired;
}
