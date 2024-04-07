#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

typedef enum {
    SIZE_BYTE = 1,
    SIZE_HALFWORD = 2,
    SIZE_WORD = 4,
} byte_size_t;

typedef enum {
    OP_READ_BYTE        = SIZE_BYTE,
    OP_READ_HALFWORD    = SIZE_HALFWORD,
    OP_READ_WORD        = SIZE_WORD,
    OP_WRITE_BYTE       = -SIZE_BYTE,
    OP_WRITE_HALFWORD   = -SIZE_HALFWORD,
    OP_WRITE_WORD       = -SIZE_WORD,
} memreg_op_t;

typedef enum {
    MEMREG_RESULT_OK,
    MEMREG_RESULT_INVALID_ACCESS,
    MEMREG_RESULT_INVALID_SIZE,
    MEMREG_RESULT_UNHANDLED,
} memreg_op_result_t;

#define OP_IS_READ(op)      ((op) > 0)
#define OP_IS_WRITE(op)     ((op) < 0)
#define OP_IS_SIZE(op, size)    ((op) == OP_READ_##size || (op) == OP_WRITE_##size)

#define OP_ASSERT_SIZE(op, size)  if ((op) != OP_READ_##size && (op) != OP_WRITE_##size) { return MEMREG_RESULT_INVALID_SIZE; }
#define OP_ASSERT_READ(op)  if ((op) < 0) { return MEMREG_RESULT_INVALID_ACCESS; }
#define OP_ASSERT_WRITE(op) if ((op) > 0) { return MEMREG_RESULT_INVALID_ACCESS; }

#define OP_RETURN_REG(reg, size)                    \
    do                                              \
    {                                               \
        if ((op) == OP_READ_##size)                 \
            *value = (reg);                         \
        else if ((op) == OP_WRITE_##size)           \
            (reg) = *value;                         \
        else                                        \
            return MEMREG_RESULT_INVALID_ACCESS;    \
        return MEMREG_RESULT_OK;                    \
    } while (0)

typedef memreg_op_result_t (*memreg_operation_t)(uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata);

typedef struct memreg_t {
    void *userdata;
    uint32_t start, end;
    memreg_operation_t operation;

    struct memreg_t *next;
} memreg_t;

memreg_t *memreg_new_simple(uint32_t start, uint8_t *data, size_t data_size);
memreg_t *memreg_new_simple_copy(uint32_t start, const uint8_t *data, size_t data_size);
memreg_t *memreg_new_operation(uint32_t start, size_t size, memreg_operation_t operation, void *data);

bool memreg_is_mapped(memreg_t *region, uint32_t addr);
uint32_t memreg_read(memreg_t *region, uint32_t addr);
void memreg_write(memreg_t *region, uint32_t addr, uint32_t value, byte_size_t size);
