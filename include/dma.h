#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct dma_t dma_t;

dma_t *dma_new(uint32_t start_addr, uint8_t *ram, size_t ram_size);
void dma_free(dma_t *);
void dma_read(dma_t *, uint32_t addr, size_t count, uint8_t *data);
void dma_write(dma_t *, uint32_t addr, size_t count, const uint8_t *data);
