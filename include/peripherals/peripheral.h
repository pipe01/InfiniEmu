#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "../memory.h"

#define OPERATION(name) memreg_op_result_t name##_operation(uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata)

#define PERIPHERAL(type, name, ...) \
    typedef struct type##_inst_t type##_t; \
    OPERATION(name); \
    type##_t *name##_new(__VA_ARGS__); \
    void name##_reset(type##_t *name);

#define NEW_PERIPH(chip, type, name, field, addr, size, ...) \
    (chip)->field = name##_new(__VA_ARGS__);       \
    name##_reset((chip)->field);                   \
    last = memreg_set_next(last, memreg_new_operation(addr, size, name##_operation, (chip)->field));
