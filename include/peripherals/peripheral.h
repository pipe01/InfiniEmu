#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "../memory.h"

#include "nrf52832/ppi.h"

#define OPERATION(name) memreg_op_result_t name##_operation(uint32_t base, uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata)

#define PERIPHERAL(type, name, ...)        \
    typedef struct type##_inst_t type##_t; \
    OPERATION(name);                       \
    type##_t *name##_new(__VA_ARGS__);

#define NEW_PERIPH(chip, type, name, field, addr, size, ...) \
    (chip)->field = name##_new(__VA_ARGS__);                 \
    last = memreg_set_next(last, memreg_new_operation(addr, size, name##_operation, (chip)->field));

#define OP_TASK_RESULT(offset, result)                                          \
    case offset:                                                                \
        if (OP_IS_READ(op))                                                     \
            *value = 0;                                                         \
        else if (*value)                                                        \
            ppi_fire_task(current_ppi, (base & 0xFF000) >> 12, TASK_ID(offset)); \
        return result;

#define OP_TASK(offset) OP_TASK_RESULT(offset, MEMREG_RESULT_OK)

#define OP_EVENT_RESULT(offset, result)                                                              \
    case offset:                                                                                     \
        if (OP_IS_READ(op))                                                                          \
            *value = ppi_event_is_set(current_ppi, (base & 0xFF000) >> 12, EVENT_ID(offset)) ? 1 : 0; \
        else if (*value == 0)                                                                        \
            ppi_clear_event(current_ppi, (base & 0xFF000) >> 12, EVENT_ID(offset));                   \
        return result;

#define OP_EVENT(offset) OP_EVENT_RESULT(offset, MEMREG_RESULT_OK)
