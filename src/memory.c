#include "memory.h"
#include "byte_util.h"

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

bool simple_operation(uint32_t offset, uint32_t *value, size_t size, void *userdata)
{
    uint8_t *data = (uint8_t *)userdata;

    WRITE_UINT32(data, offset, *value);

    return true;
}

memreg_t *memreg_new_simple(uint32_t start, uint8_t *data, size_t size)
{
    memreg_t *region = malloc(sizeof(memreg_t));
    memset(region, 0, sizeof(memreg_t));

    region->userdata = data;
    region->start = start;
    region->end = start + size;
    region->operation = simple_operation;

    return region;
}

uint32_t memreg_read(memreg_t *region, uint32_t addr)
{
    uint32_t value;

    while (region)
    {
        if (addr >= region->start && addr < region->end)
        {
            if (region->operation(addr - region->start, &value, SIZE_WORD, region->userdata))
                return value;
        }

        region = region->next;
    }

    printf("Tried to read from unmapped memory at 0x%08X\n", addr);
    abort(); // TODO: Handle this better
}

void memreg_write(memreg_t *region, uint32_t addr, uint32_t value, size_t size)
{
    while (region)
    {
        if (addr >= region->start && addr < region->end)
        {
            region->operation(addr - region->start, &value, size, region->userdata);
            return;
        }

        region = region->next;
    }

    abort(); // TODO: Handle this better
}