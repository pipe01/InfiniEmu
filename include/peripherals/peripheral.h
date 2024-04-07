#pragma once

#include <stdbool.h>
#include <stdint.h>

#define OPERATION(name) bool name##_operation(uint32_t offset, uint32_t *value, int op, void *userdata)

#define PERIPHERAL(type, name) \
    typedef struct type##_inst_t type##_t; \
    OPERATION(name); \
    type##_t *name##_new(); \
    void name##_reset(type##_t *name);
