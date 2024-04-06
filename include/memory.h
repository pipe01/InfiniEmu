#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SIZE_BYTE       1
#define SIZE_HALFWORD   2
#define SIZE_WORD       4

#define OP_READ_BYTE        SIZE_BYTE
#define OP_READ_HALFWORD    SIZE_HALFWORD
#define OP_READ_WORD        SIZE_WORD
#define OP_WRITE_BYTE       -SIZE_BYTE
#define OP_WRITE_HALFWORD   -SIZE_HALFWORD
#define OP_WRITE_WORD       -SIZE_WORD

typedef bool (*memreg_operation_t)(uint32_t offset, uint32_t *value, int op, void *userdata);

typedef struct memreg_t {
    void *userdata;
    uint32_t start, end;
    memreg_operation_t operation;

    struct memreg_t *next;
} memreg_t;

memreg_t *memreg_new_simple(uint32_t start, uint8_t *data, size_t data_size);
memreg_t *memreg_new_simple_copy(uint32_t start, const uint8_t *data, size_t data_size);
memreg_t *memreg_new_operation(uint32_t start, size_t size, memreg_operation_t operation, void *data);

uint32_t memreg_read(memreg_t *region, uint32_t addr);
void memreg_write(memreg_t *region, uint32_t addr, uint32_t value, size_t size);
