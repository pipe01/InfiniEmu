#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#define SIZE_BYTE       1
#define SIZE_HALFWORD   2
#define SIZE_WORD       4

#define OP_READ_BYTE        SIZE_BYTE
#define OP_READ_HALFWORD    SIZE_HALFWORD
#define OP_READ_WORD        SIZE_WORD
#define OP_WRITE_BYTE       -SIZE_BYTE
#define OP_WRITE_HALFWORD   -SIZE_HALFWORD
#define OP_WRITE_WORD       -SIZE_WORD

#define OP_IS_READ(op)      ((op) > 0)
#define OP_IS_WRITE(op)     ((op) < 0)

#define OP_ASSERT_SIZE(op, size)  if ((op) != OP_READ_##size && (op) != OP_WRITE_##size) { printf("Invalid operation %d\n", op); abort(); }
#define OP_ASSERT_READ(op)  if ((op) < 0) { printf("Invalid operation %d\n", op); abort(); }
#define OP_ASSERT_WRITE(op) if ((op) > 0) { printf("Invalid operation %d\n", op); abort(); }

#define OP_RETURN_REG(reg, size)       \
    do                                      \
    {                                       \
        if ((op) == OP_READ_##size)         \
            *value = reg;                   \
        else if ((op) == OP_WRITE_##size)   \
            reg = *value;                   \
        return true;                        \
    } while (0)

typedef bool (*memreg_operation_t)(uint32_t offset, uint32_t *value, int op, void *userdata);

#define OPERATION(name) bool name##_operation(uint32_t offset, uint32_t *value, int op, void *userdata)

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
void memreg_write(memreg_t *region, uint32_t addr, uint32_t value, size_t size);
