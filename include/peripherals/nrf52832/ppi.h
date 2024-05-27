#pragma once

#include "peripherals/peripheral.h"

typedef struct PPI_t PPI_t;

// OPERATION(ppi);
memreg_op_result_t ppi_operation(uint32_t base, uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata);

_Thread_local extern PPI_t *current_ppi; // TODO: Remove this and pass PPI instance to peripherals

typedef void (*ppi_task_cb_t)(uint8_t task, void *userdata);

#define TASK_HANDLER(periph, name) void periph##_##name##_handler(ppi_tasks_t task, void *userdata)
#define TASK_HANDLER_SHORT(periph, name, type, fn) TASK_HANDLER(periph, name) { type *p = ((type *)userdata); (void)p; fn; }

#define PPI_ID(periph, id) (((periph) << 8) | (id))
#define PPI_ID_FROM_ADDRESS(base, offset) ((((base) & 0xFF000) >> 4) | ((offset) & 0xFF))

PPI_t *ppi_new();

void ppi_fire_task(PPI_t *, uint16_t task_id);
void ppi_on_task(PPI_t *, uint16_t task_id, ppi_task_cb_t cb, void *userdata);

void ppi_fire_event(PPI_t *, uint16_t event_id);
void ppi_clear_event(PPI_t *, uint16_t event_id);
bool ppi_event_is_set(PPI_t *, uint16_t event_id);
