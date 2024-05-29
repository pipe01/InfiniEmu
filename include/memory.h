#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#include "config.h"

#define MEMREG_FIND_NOT_FOUND 0xFFFFFFFF

typedef enum __attribute__((packed)) {
    SIZE_BYTE = 1,
    SIZE_HALFWORD = 2,
    SIZE_WORD = 4,
} byte_size_t;

static inline uint32_t size_mask(byte_size_t size)
{
    return size == SIZE_WORD ? 0xFFFFFFFF : (uint32_t)((1 << (size * 8)) - 1);
}

typedef enum {
    OP_RESET            = 0,
    OP_READ_BYTE        = SIZE_BYTE,
    OP_READ_HALFWORD    = SIZE_HALFWORD,
    OP_READ_WORD        = SIZE_WORD,
    OP_WRITE_BYTE       = -SIZE_BYTE,
    OP_WRITE_HALFWORD   = -SIZE_HALFWORD,
    OP_WRITE_WORD       = -SIZE_WORD,
} memreg_op_t;

typedef enum {
    MEMREG_RESULT_OK,
    MEMREG_RESULT_OK_CONTINUE,
    MEMREG_RESULT_INVALID_ACCESS,
    MEMREG_RESULT_INVALID_SIZE,
    MEMREG_RESULT_UNHANDLED,
} memreg_op_result_t;

#define OP_IS_READ(op)      ((op) > 0)
#define OP_IS_WRITE(op)     ((op) < 0)
#define OP_IS_SIZE(op, size)    ((op) == OP_READ_##size || (op) == OP_WRITE_##size)

#ifdef ABORT_ON_INVALID_MEM_ACCESS
#define OP_INVALID_ACCESS abort()
#define OP_INVALID_SIZE abort()
#else
#define OP_INVALID_ACCESS return MEMREG_RESULT_INVALID_ACCESS
#define OP_INVALID_SIZE return MEMREG_RESULT_INVALID_SIZE
#endif

#define OP_ASSERT_SIZE(op, size)  if ((op) != OP_READ_##size && (op) != OP_WRITE_##size) { OP_INVALID_SIZE; }
#define OP_ASSERT_READ(op)  if ((op) < 0) { OP_INVALID_ACCESS; }
#define OP_ASSERT_WRITE(op) if ((op) > 0) { OP_INVALID_ACCESS; }

#define OP_RETURN_REG_RESULT(reg, size, result)     \
    do                                              \
    {                                               \
        if ((op) == OP_READ_##size)                 \
            *value = (reg);                         \
        else if ((op) == OP_WRITE_##size)           \
            (reg) = *value;                         \
        else                                        \
            return MEMREG_RESULT_INVALID_SIZE;      \
        return (result);                    \
    } while (0)

#define OP_RETURN_REG(reg, size) OP_RETURN_REG_RESULT(reg, size, MEMREG_RESULT_OK)

typedef memreg_op_result_t (*memreg_operation_t)(uint32_t base, uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata);

typedef struct memreg_inst_t memreg_t;

memreg_t *memreg_new_simple(uint32_t start, uint8_t *data, size_t data_size);
memreg_t *memreg_new_simple_readonly(uint32_t start, const uint8_t *data, size_t data_size);
memreg_t *memreg_new_simple_copy(uint32_t start, const uint8_t *data, size_t data_size);
memreg_t *memreg_new_operation(uint32_t start, size_t size, memreg_operation_t operation, void *data);
void memreg_free(memreg_t *region);

// Resets this memory region
void memreg_reset(memreg_t *region);

// Resets this memory region and all of its children recursively
void memreg_reset_all(memreg_t *region);

bool memreg_is_mapped(memreg_t *region, uint32_t addr);
uint32_t memreg_read(memreg_t *region, uint32_t addr);
uint8_t memreg_read_byte(memreg_t *region, uint32_t addr);
uint16_t memreg_read_halfword(memreg_t *region, uint32_t addr);
void memreg_write(memreg_t *region, uint32_t addr, uint32_t value, byte_size_t size);

uint32_t memreg_find_data(memreg_t *region, uint32_t start_addr, uint32_t search_length, uint8_t *data, size_t data_size);

memreg_t *memreg_set_next(memreg_t *region, memreg_t *next);
memreg_t *memreg_find_last(memreg_t *region);
