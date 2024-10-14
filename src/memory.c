#include "memory.h"

#include "byte_util.h"
#include "fault.h"

#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define MAX_BREAKPOINTS 5

struct memreg_t
{
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

    return region;
}

void memreg_free(memreg_t *region)
{
    if (region->free_userdata)
        free(region->userdata);
    free(region);
}

void memreg_reset(memreg_t *region)
{
    region->operation(0, 0, NULL, OP_RESET, region->userdata);
}

uint32_t memreg_get_start(memreg_t *region)
{
    return region->start;
}

uint32_t memreg_get_end(memreg_t *region)
{
    return region->end;
}

void *memreg_get_userdata(memreg_t *region)
{
    return region->userdata;
}

typedef struct
{
    memreg_t **regions;
    uint16_t regions_count;
} membucket_t;

#define BUCKET1_COUNT 16
#define BUCKET2_COUNT 256
#define BUCKET_SIZE 0x1000

struct memory_map_t
{
    membucket_t buckets[BUCKET1_COUNT][BUCKET2_COUNT];
};

memory_map_t *memory_map_new()
{
    memory_map_t *map = calloc(1, sizeof(memory_map_t));
    return map;
}

void memory_map_free(memory_map_t *map)
{
    assert(false); // TODO: Implement
}

void memory_map_reset(memory_map_t *map)
{
    for (size_t i = 0; i < BUCKET1_COUNT; i++)
    {
        for (size_t j = 0; j < BUCKET2_COUNT; j++)
        {
            membucket_t *bucket = &map->buckets[i][j];

            for (size_t k = 0; k < bucket->regions_count; k++)
                memreg_reset(bucket->regions[k]);
        }
    }
}

void memory_bucket_add_region(membucket_t *bucket, memreg_t *region)
{
    assert(bucket->regions_count < BUCKET_SIZE);

    memreg_t **new_regions = malloc((bucket->regions_count + 1) * sizeof(memreg_t *));
    memreg_t *next_insert = region;

    // Insert the new region in sorted order
    for (uint8_t i = 0; i < bucket->regions_count + 1; i++)
    {
        if (i == bucket->regions_count)
        {
            new_regions[i] = next_insert;
        }
        else if (bucket->regions[i]->start < next_insert->start)
        {
            new_regions[i] = bucket->regions[i];
        }
        else
        {
            new_regions[i] = next_insert;
            next_insert = bucket->regions[i];
        }
    }

    free(bucket->regions);
    bucket->regions = new_regions;
    bucket->regions_count++;
}

inline static membucket_t *memory_map_find_bucket(memory_map_t *map, uint32_t addr)
{
    uint8_t bucket1 = (addr >> 28) & 0xF;
    uint8_t bucket2 = (addr >> 12) & 0xFF;

    return &map->buckets[bucket1][bucket2];
}

void memory_map_add_region(memory_map_t *map, memreg_t *region)
{
    for (uint32_t i = region->start; i < region->end; i += BUCKET_SIZE)
    {
        memory_bucket_add_region(memory_map_find_bucket(map, i), region);
    }
}

memreg_t *memory_map_get_region(memory_map_t *map, uint32_t addr)
{
    membucket_t *bucket = memory_map_find_bucket(map, addr);

    if (bucket->regions_count == 0)
        return NULL;

    if (bucket->regions_count == 1)
        return bucket->regions[0];

    for (uint8_t i = 0; i < bucket->regions_count; i++)
    {
        memreg_t *region = bucket->regions[i];

        if (addr >= region->start && addr < region->end)
            return region;
    }

    return NULL;
}

void memory_map_do_operation(memory_map_t *map, uint32_t addr, memreg_op_t op, uint32_t *value)
{
    membucket_t *bucket = memory_map_find_bucket(map, addr);

    memreg_op_result_t result = MEMREG_RESULT_UNHANDLED;
    bool handled = false;

    for (size_t i = 0; i < bucket->regions_count; i++)
    {
        memreg_t *region = bucket->regions[i];

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

uint32_t memory_map_find_data(memory_map_t *map, uint32_t start_addr, uint32_t search_length, const uint8_t *data, size_t data_size)
{
    assert(search_length > 0);
    assert(data_size > 0);

    size_t match_len = 0;

    for (uint32_t addr = start_addr; addr < start_addr + search_length; addr++)
    {
        if (memory_map_read_byte(map, addr) == data[match_len])
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
