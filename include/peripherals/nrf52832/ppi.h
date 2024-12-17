#pragma once

#include "peripherals/peripheral.h"

typedef struct PPI_t PPI_t;

typedef enum
{
    SHORT_RADIO_READY_START = 0,
    SHORT_RADIO_END_DISABLE,
    SHORT_RADIO_DISABLED_TXEN,
    SHORT_RADIO_DISABLED_RXEN,
    SHORT_RADIO_ADDRESS_RSSISTART,
    SHORT_RADIO_END_START,
    SHORT_RADIO_ADDRESS_BCSTART,
    SHORT_RADIO_DISABLED_RSSISTOP,
} ppi_short_t;

// OPERATION(ppi);
memreg_op_result_t ppi_operation(uint32_t base, uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata);

_Thread_local extern PPI_t *current_ppi; // TODO: Remove this and pass PPI instance to peripherals

typedef void (*ppi_task_cb_t)(PPI_t *, uint8_t peripheral, uint8_t task, void *userdata);

#define PPI_TASK_HANDLER(name) void name(PPI_t *ppi, uint8_t peripheral, uint8_t task, void *userdata)

#define TASK_ID(offset) (((offset) & 0xFF) / 4)
#define EVENT_ID(offset) (((offset) & 0xFF) / 4)

PPI_t *ppi_new(cpu_t **cpu);

void ppi_add_peripheral(PPI_t *, uint8_t id, ppi_task_cb_t cb, void *userdata);
void ppi_replace_peripheral(PPI_t *, uint8_t id, ppi_task_cb_t cb, void *userdata);
void ppi_remove_peripheral(PPI_t *, uint8_t id);
void ppi_fire_task(PPI_t *, uint8_t peripheral_id, uint8_t task_id);

void ppi_fire_event(PPI_t *, uint8_t peripheral_id, uint8_t event_id, bool pend_exception);
void ppi_clear_event(PPI_t *, uint8_t peripheral_id, uint8_t event_id);
bool ppi_event_is_set(PPI_t *, uint8_t peripheral_id, uint8_t event_id);

void ppi_shorts_set_enabled(PPI_t *, ppi_short_t short_id, bool enabled);
bool ppi_shorts_is_enabled(PPI_t *, ppi_short_t short_id);
