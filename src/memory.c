#include "memory.h"

#include "byte_util.h"
#include "fault.h"

#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define MAX_BREAKPOINTS 5

struct memreg_inst_t
{
    memreg_t *next;

    void *userdata;
    bool free_userdata;

    uint32_t start, end;
    memreg_operation_t operation;

    uint32_t breakpoints[MAX_BREAKPOINTS];
    size_t breakpoint_count;
};

static memreg_op_result_t simple_operation(uint32_t base, uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata)
{
    uint8_t *data = (uint8_t *)userdata;

    switch (op)
    {
    case OP_READ_BYTE:
        *value = data[offset];
        break;

    case OP_READ_HALFWORD:
        *value = READ_UINT16(data, offset);
        break;

    case OP_READ_WORD:
        *value = READ_UINT32(data, offset);
        break;

    case OP_WRITE_BYTE:
        data[offset] = *value;
        break;

    case OP_WRITE_HALFWORD:
        WRITE_UINT16(data, offset, *value);
        break;

    case OP_WRITE_WORD:
        WRITE_UINT32(data, offset, *value);
        break;

    default:
        return MEMREG_RESULT_UNHANDLED;
    }

    return MEMREG_RESULT_OK;
}

static memreg_op_result_t simple_operation_readonly(uint32_t base, uint32_t offset, uint32_t *value, memreg_op_t op, void *userdata)
{
    uint8_t *data = (uint8_t *)userdata;

    switch (op)
    {
    case OP_READ_BYTE:
        *value = data[offset];
        break;

    case OP_READ_HALFWORD:
        *value = READ_UINT16(data, offset);
        break;

    case OP_READ_WORD:
        *value = READ_UINT32(data, offset);
        break;

    case OP_WRITE_BYTE:
    case OP_WRITE_HALFWORD:
    case OP_WRITE_WORD:
        return MEMREG_RESULT_INVALID_ACCESS;

    default:
        return MEMREG_RESULT_UNHANDLED;
    }

    return MEMREG_RESULT_OK;
}

memreg_t *memreg_new_simple(uint32_t start, uint8_t *data, size_t data_size)
{
    return memreg_new_operation(start, data_size, simple_operation, data);
}

memreg_t *memreg_new_simple_readonly(uint32_t start, const uint8_t *data, size_t data_size)
{
    return memreg_new_operation(start, data_size, simple_operation_readonly, (uint8_t *)data);
}

memreg_t *memreg_new_simple_copy(uint32_t start, const uint8_t *data, size_t data_size)
{
    uint8_t *data_copy = malloc(data_size);
    memcpy(data_copy, data, data_size);

    memreg_t *region = memreg_new_simple(start, data_copy, data_size);
    region->free_userdata = true;

    return region;
}

memreg_t *memreg_new_operation(uint32_t start, size_t size, memreg_operation_t operation, void *data)
{
    memreg_t *region = calloc(1, sizeof(memreg_t));

    region->userdata = data;
    region->free_userdata = false;
    region->start = start;
    region->end = start + size;
    region->operation = operation;
    region->next = NULL;

    return region;
}

void memreg_free(memreg_t *region)
{
    while (region)
    {
        memreg_t *next = region->next;

        if (region->free_userdata)
            free(region->userdata);
        free(region);

        region = next;
    }
}

void memreg_reset(memreg_t *region)
{
    region->operation(0, 0, NULL, OP_RESET, region->userdata);
}

void memreg_reset_all(memreg_t *region)
{
    while (region)
    {
        memreg_reset(region);

        region = region->next;
    }
}

memreg_t *memreg_set_next(memreg_t *region, memreg_t *next)
{
    if (!region)
        return region;

    return region->next = next;
}

memreg_t *memreg_find_last(memreg_t *region)
{
    if (!region)
        return NULL;

    while (region->next)
        region = region->next;

    return region;
}

bool memreg_is_mapped(memreg_t *region, uint32_t addr)
{
    while (region)
    {
        if (addr >= region->start && addr < region->end)
            return true;

        region = region->next;
    }

    return false;
}

void memreg_do_operation(memreg_t *region, uint32_t addr, memreg_op_t op, uint32_t *value)
{
    memreg_op_result_t result = MEMREG_RESULT_UNHANDLED;
    bool handled = false;

    while (region)
    {
        if (addr >= region->start && addr < region->end)
        {
            result = region->operation(region->start, addr - region->start, value, op, region->userdata);

            if (result == MEMREG_RESULT_OK)
                return;
            else if (result == MEMREG_RESULT_OK_CONTINUE)
                handled = true;
            else if (result != MEMREG_RESULT_UNHANDLED)
                break;
        }

        region = region->next;
    }

    if (handled)
        return;

    switch (result)
    {
    case MEMREG_RESULT_INVALID_ACCESS:
        printf("Invalid memory access at 0x%08X\n", addr);
        fault_take(FAULT_MEMORY_INVALID_ACCESS);
        break;

    case MEMREG_RESULT_INVALID_SIZE:
        printf("Invalid memory access size at 0x%08X\n", addr);
        fault_take(FAULT_MEMORY_INVALID_SIZE);
        break;

    case MEMREG_RESULT_UNHANDLED:
        printf("Tried to access unmapped memory at 0x%08X\n", addr);
        fault_take(FAULT_MEMORY_UNHANDLED);
        break;

    default:
        printf("Unknown error on memory operation at 0x%08X\n", addr);
        fault_take(FAULT_UNKNOWN);
    }
}

uint32_t memreg_read(memreg_t *region, uint32_t addr)
{
    uint32_t value;
    memreg_do_operation(region, addr, OP_READ_WORD, &value);
    return value;
}

uint8_t memreg_read_byte(memreg_t *region, uint32_t addr) {
    uint32_t value;
    memreg_do_operation(region, addr, OP_READ_BYTE, &value);
    return (uint8_t)value;
}

uint16_t memreg_read_halfword(memreg_t *region, uint32_t addr) {
    uint32_t value;
    memreg_do_operation(region, addr, OP_READ_HALFWORD, &value);
    return (uint16_t)value;
}

inline void memreg_write(memreg_t *region, uint32_t addr, uint32_t value, byte_size_t size)
{
    memreg_do_operation(region, addr, -size, &value);
}

uint32_t memreg_find_data(memreg_t *region, uint32_t start_addr, uint32_t search_length, uint8_t *data, size_t data_size)
{
    assert(search_length > 0);
    assert(data_size > 0);

    size_t match_len = 0;

    for (uint32_t addr = start_addr; addr < start_addr + search_length; addr++)
    {
        if (memreg_read_byte(region, addr) == data[match_len])
        {
            match_len++;

            if (match_len == data_size)
                return addr - data_size + 1;
        }
        else
        {
            match_len = 0;
        }
    }

    return MEMREG_FIND_NOT_FOUND;
}

memreg_t *memreg_get_next(memreg_t *region)
{
    return region->next;
}

uint32_t memreg_get_start(memreg_t *region)
{
    return region->start;
}

void *memreg_get_userdata(memreg_t *region)
{
    return region->userdata;
}
