#include "config.h"

#if ENABLE_SEGGER_RTT

#if ENABLE_LOG_SEGGER_RTT
#define LOG(msg, ...) printf("[RTT] " msg, __VA_ARGS__)
#else
#define LOG(...)
#endif

#include "segger_rtt.h"

#include <stdlib.h>
#include <string.h>

#include "../lib/RTT/RTT/SEGGER_RTT.h"
#include "byte_util.h"

#define BUFFER_UP_FIELD(cb_addr, buf_index, offset) ((cb_addr) + offsetof(SEGGER_RTT_CB, aUp) + (24 * (buf_index)) + (offset))

#define min(a, b) ((a) < (b) ? (a) : (b))

struct rtt_inst_t
{
    memory_map_t *mem;
    uint32_t control_block_addr;
    uint32_t up_buf_size;
};

rtt_t *rtt_new(memory_map_t *mem)
{
    rtt_t *rtt = malloc(sizeof(rtt_t));
    rtt->mem = mem;
    rtt->control_block_addr = 0;

    return rtt;
}

void rtt_free(rtt_t *rtt)
{
    free(rtt);
}

bool rtt_find_control(rtt_t *rtt)
{
    if (rtt->control_block_addr != 0)
        return true;

    uint32_t addr = memory_map_find_data(rtt->mem, x(2000, 0000), 0x10000, (const uint8_t *)"SEGGER RTT", 10);
    if (addr == MEMREG_FIND_NOT_FOUND)
        return false;

    LOG("Found SEGGER RTT control block at 0x%08x\n", addr);

    rtt->control_block_addr = addr;

    uint32_t upName = memory_map_read(rtt->mem, BUFFER_UP_FIELD(addr, 0, 0));

    char name[32];
    for (size_t i = 0; i < sizeof(name); i++)
    {
        if ((name[i] = memory_map_read(rtt->mem, upName + i)) == 0)
            break;
    }

    rtt->up_buf_size = memory_map_read(rtt->mem, BUFFER_UP_FIELD(addr, 0, 8));

    LOG("Up buffer name: %s, %d bytes\n", name, rtt->up_buf_size);

    return true;
}

size_t rtt_flush_buffers(rtt_t *rtt, char *buffer, size_t buffer_size)
{
    if (rtt->control_block_addr == 0)
        return 0;

    uint32_t cb_addr = rtt->control_block_addr;

    uint32_t bufferAddr = memory_map_read(rtt->mem, BUFFER_UP_FIELD(cb_addr, 0, 4));
    uint32_t wrOff = memory_map_read(rtt->mem, BUFFER_UP_FIELD(cb_addr, 0, 12));
    uint32_t rdOff = memory_map_read(rtt->mem, BUFFER_UP_FIELD(cb_addr, 0, 16));

    size_t numBytesRem, numBytesRead = 0;

    if (rdOff > wrOff)
    {
        numBytesRem = rtt->up_buf_size - rdOff;
        numBytesRem = min(numBytesRem, buffer_size);
        bufferAddr += rdOff;
        numBytesRead += numBytesRem;
        buffer_size -= numBytesRem;
        rdOff += numBytesRem;

        while (numBytesRem--)
        {
            *buffer++ = memory_map_read_byte(rtt->mem, bufferAddr++);
        }

        if (rdOff == rtt->up_buf_size)
            rdOff = 0;
    }

    numBytesRem = wrOff - rdOff;
    numBytesRem = min(numBytesRem, buffer_size);

    if (numBytesRem > 0)
    {
        bufferAddr += rdOff;
        numBytesRead += numBytesRem;
        buffer_size -= numBytesRem;
        rdOff += numBytesRem;

        while (numBytesRem--)
        {
            *buffer++ = memory_map_read_byte(rtt->mem, bufferAddr++);
        }
    }

    if (numBytesRead)
    {
        memory_map_write(rtt->mem, BUFFER_UP_FIELD(cb_addr, 0, 16), rdOff, SIZE_WORD);
    }

    return numBytesRead;
}

#else

void pedantic() {}

#endif