#include "memory.h"
#include "byte_util.h"

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

bool simple_operation(uint32_t offset, uint32_t *value, int op, void *userdata)
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
        printf("Unhandled operation %d\n", op);
        abort();
    }

    return true;
}

memreg_t *memreg_new_simple(uint32_t start, uint8_t *data, size_t data_size)
{
    return memreg_new_operation(start, data_size, simple_operation, data);
}

memreg_t *memreg_new_simple_copy(uint32_t start, const uint8_t *data, size_t data_size)
{
    uint8_t *data_copy = malloc(data_size);
    memcpy(data_copy, data, data_size);

    return memreg_new_simple(start, data_copy, data_size);
}

memreg_t *memreg_new_operation(uint32_t start, size_t size, memreg_operation_t operation, void *data)
{
    memreg_t *region = malloc(sizeof(memreg_t));

    region->userdata = data;
    region->start = start;
    region->end = start + size;
    region->operation = operation;
    region->next = NULL;

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

uint32_t memreg_read(memreg_t *region, uint32_t addr)
{
    uint32_t value;

    while (region)
    {
        if (addr >= region->start && addr < region->end)
        {
            if (region->operation(addr - region->start, &value, OP_READ_WORD, region->userdata))
                return value;
        }

        region = region->next;
    }

    printf("Tried to read from unmapped memory at 0x%08X\n", addr);
    abort(); // TODO: Handle this better
}

void memreg_write(memreg_t *region, uint32_t addr, uint32_t value, size_t size)
{
    printf("Writing to 0x%08X: 0x%08X, size: %ld\n", addr, value, size);

    while (region)
    {
        if (addr >= region->start && addr < region->end)
        {
            region->operation(addr - region->start, &value, -size, region->userdata);
            return;
        }

        region = region->next;
    }

    abort(); // TODO: Handle this better
}