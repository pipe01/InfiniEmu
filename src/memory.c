#include "memory.h"
#include "byte_util.h"

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

void simple_write(uint32_t offset, uint32_t value, void *userdata)
{
    uint8_t *data = (uint8_t *)userdata;

    WRITE_UINT32(data, offset, value);
}

uint32_t simple_read(uint32_t offset, void *userdata)
{
    uint8_t *data = (uint8_t *)userdata;

    return READ_UINT32(data, offset);
}

memreg_t *memreg_new_simple(uint32_t start, uint8_t *data, size_t size)
{
    memreg_t *region = malloc(sizeof(memreg_t));
    memset(region, 0, sizeof(memreg_t));

    region->userdata = data;
    region->start = start;
    region->end = start + size;

    return region;
}

uint32_t memreg_read(memreg_t *region, uint32_t addr)
{
    while (region)
    {
        if (addr >= region->start && addr < region->end)
            return region->read(addr - region->start, region->userdata);

        region = region->next;
    }

    abort(); // TODO: Handle this better
}

void memreg_write(memreg_t *region, uint32_t addr, uint32_t value)
{
    while (region)
    {
        if (addr >= region->start && addr < region->end)
        {
            region->write(addr - region->start, value, region->userdata);
            return;
        }

        region = region->next;
    }

    abort(); // TODO: Handle this better
}