#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "bus_i2c.h"
#include "bus_spi.h"
#include "cpu.h"
#include "dma.h"
#include "memory.h"
#include "pins.h"
#include "ticker.h"

typedef struct
{
    uint8_t id;
    cpu_t **cpu;
    pins_t *pins;
    struct PPI_t *ppi;
    ticker_t *ticker;
    bus_i2c_t *i2c;
    bus_spi_t *spi;
    dma_t *dma;
} nrf52_peripheral_context_t;

#define OPERATION(name) memreg_op_result_t name##_operation(uint32_t base, uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata)

#define NRF52_PERIPHERAL_CONSTRUCTOR(type, name, ...) type##_t *name##_new(nrf52_peripheral_context_t ctx, ##__VA_ARGS__)

#define PERIPHERAL(type, name, ...)        \
    typedef struct type##_inst_t type##_t; \
    OPERATION(name);                       \
    type##_t *name##_new(__VA_ARGS__);

#define NRF52_PERIPHERAL(type, name, ...)  \
    typedef struct type##_inst_t type##_t; \
    OPERATION(name);                       \
    type##_t *name##_new(nrf52_peripheral_context_t ctx, ##__VA_ARGS__);

#define NEW_PERIPH(chip, type, name, field, addr, size, ...) \
    (chip)->field = name##_new(__VA_ARGS__);                 \
    memory_map_add_region((chip)->mem, memreg_new_operation(addr, size, name##_operation, (chip)->field));

#define OP_TASK_RESULT(offset, result)                                           \
    case offset:                                                                 \
        if (OP_IS_READ(op))                                                      \
            *value = 0;                                                          \
        else if (*value)                                                         \
            ppi_fire_task(current_ppi, (base & 0xFF000) >> 12, TASK_ID(offset)); \
        return result;

#define OP_TASK(offset) OP_TASK_RESULT(offset, MEMREG_RESULT_OK)

#define OP_EVENT_RESULT(offset, result)                                                               \
    case offset:                                                                                      \
        if (OP_IS_READ(op))                                                                           \
            *value = ppi_event_is_set(current_ppi, (base & 0xFF000) >> 12, EVENT_ID(offset)) ? 1 : 0; \
        else if (*value == 0)                                                                         \
            ppi_clear_event(current_ppi, (base & 0xFF000) >> 12, EVENT_ID(offset));                   \
        return result;

#define OP_EVENT(offset) OP_EVENT_RESULT(offset, MEMREG_RESULT_OK)

#define OP_RETURN_REG_SET(reg, size) \
    if (OP_IS_READ(op))              \
        *value = reg;                \
    else                             \
        reg |= *value;               \
    return MEMREG_RESULT_OK;

#define OP_RETURN_REG_CLR(reg, size) \
    if (OP_IS_READ(op))              \
        *value = reg;                \
    else                             \
        reg &= ~*value;              \
    return MEMREG_RESULT_OK;

#define OP_INTEN(peripheral) \
    case 0x300:              \
        OP_RETURN_REG(peripheral->inten.value, WORD);

#define OP_INTENSET(peripheral) \
    case 0x304:                 \
        OP_RETURN_REG_SET(peripheral->inten.value, WORD)

#define OP_INTENCLR(peripheral) \
    case 0x308:                 \
        OP_RETURN_REG_CLR(peripheral->inten.value, WORD)
