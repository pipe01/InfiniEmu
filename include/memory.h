#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct memreg_t {
    void *userdata;
    uint32_t start, end;
    uint32_t (*read)(uint32_t offset, void *userdata);
    void (*write)(uint32_t offset, uint32_t value, void *userdata);

    struct memreg_t *next;
} memreg_t;

memreg_t *memreg_new_simple(uint32_t start, uint8_t *data, size_t size);

uint32_t memreg_read(memreg_t *region, uint32_t addr);
void memreg_write(memreg_t *region, uint32_t addr, uint32_t value);
