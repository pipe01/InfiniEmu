#include "dma.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct dma_t
{
    uint32_t start_addr;
    uint8_t *ram;
    size_t ram_size;
};

dma_t *dma_new(uint32_t start_addr, uint8_t *ram, size_t ram_size)
{
    dma_t *edma = malloc(sizeof(dma_t));
    edma->start_addr = start_addr;
    edma->ram = ram;
    edma->ram_size = ram_size;

    return edma;
}

void dma_free(dma_t *edma)
{
    free(edma);
}

void dma_read(dma_t *edma, uint32_t addr, size_t count, uint8_t *data)
{
    assert(addr >= edma->start_addr);
    uint32_t offset = addr - edma->start_addr;
    assert(offset + count <= edma->ram_size);

    memcpy(data, edma->ram + offset, count);
}

void dma_write(dma_t *edma, uint32_t addr, size_t count, const uint8_t *data)
{
    assert(addr >= edma->start_addr);
    uint32_t offset = addr - edma->start_addr;
    assert(offset + count <= edma->ram_size);

    memcpy(edma->ram + offset, data, count);
}
