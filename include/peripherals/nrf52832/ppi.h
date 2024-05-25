#pragma once

#include "memory.h"

typedef struct PPI_t PPI_t;

memreg_op_result_t ppi_operation(uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata);

typedef enum
{
    PPI_EVENT_CLOCK_LFCLKSTARTED,
    PPI_EVENT_RNG_VALRDY,
    PPI_EVENT_RTC_TICK,
    PPI_EVENT_RTC_OVRFLW,
    PPI_EVENT_RTC_COMPARE0,
    PPI_EVENT_RTC_COMPARE1,
    PPI_EVENT_RTC_COMPARE2,
    PPI_EVENT_RTC_COMPARE3,
    PPI_EVENT_SPIM_STOPPED,
    PPI_EVENT_SPIM_ENDRX,
    PPI_EVENT_SPIM_END,
    PPI_EVENT_SPIM_ENDTX,
    PPI_EVENT_SPIM_STARTED,
    PPI_EVENT_TWIM_STOPPED,
    PPI_EVENT_TWIM_ERROR,
    PPI_EVENT_TWIM_SUSPENDED,
    PPI_EVENT_TWIM_RXSTARTED,
    PPI_EVENT_TWIM_TXSTARTED,
    PPI_EVENT_TWIM_LASTRX,
    PPI_EVENT_TWIM_LASTTX,

    PPI_EVENTS_COUNT
} ppi_events_t;

typedef enum
{
    PPI_TASK_CLOCK_LFCLKSTART,
    PPI_TASK_RNG_START,
    PPI_TASK_RTC_START,
    PPI_TASK_RTC_STOP,
    PPI_TASK_RTC_CLEAR,
    PPI_TASK_SPIM_START,
    PPI_TASK_TWIM_STARTRX,
    PPI_TASK_TWIM_STARTTX,
    PPI_TASK_TWIM_STOP,
    PPI_TASK_TWIM_SUSPEND,
    PPI_TASK_TWIM_RESUME,

    PPI_TASKS_COUNT
} ppi_tasks_t;

_Thread_local extern PPI_t *current_ppi; // TODO: Remove this and pass PPI instance to peripherals

typedef void (*ppi_task_cb_t)(ppi_tasks_t task, void *userdata);

#define TASK_HANDLER(periph, name) void periph##_##name##_handler(ppi_tasks_t task, void *userdata)
#define TASK_HANDLER_SHORT(periph, name, type, fn) TASK_HANDLER(periph, name) { type *p = ((type *)userdata); fn; }

PPI_t *ppi_new();

void ppi_fire_task(PPI_t *, ppi_tasks_t task);
void ppi_on_task(PPI_t *, ppi_tasks_t task, ppi_task_cb_t cb, void *userdata);

void ppi_fire_event(PPI_t *, ppi_events_t event);
void ppi_clear_event(PPI_t *, ppi_events_t event);
bool ppi_event_is_set(PPI_t *, ppi_events_t event);
