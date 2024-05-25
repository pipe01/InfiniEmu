#pragma once

#include "memory.h"

typedef struct PPI_t PPI_t;

memreg_op_result_t ppi_operation(uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata);

typedef enum
{
    PPI_EVENT_CLOCK_LFCLKSTARTED,

    PPI_EVENTS_COUNT
} ppi_events_t;

typedef enum
{
    PPI_TASK_CLOCK_LFCLKSTART,

    PPI_TASKS_COUNT
} ppi_tasks_t;

_Thread_local extern PPI_t *current_ppi; // TODO: Remove this and pass PPI instance to peripherals

typedef void (*ppi_task_cb_t)(ppi_tasks_t task, void *userdata);

PPI_t *ppi_new();

void ppi_fire_task(PPI_t *, ppi_tasks_t task);
void ppi_on_task(PPI_t *, ppi_tasks_t task, ppi_task_cb_t cb, void *userdata);

void ppi_fire_event(PPI_t *, ppi_events_t event);
void ppi_clear_event(PPI_t *, ppi_events_t event);
bool ppi_event_is_set(PPI_t *, ppi_events_t event);
