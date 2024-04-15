#include "config.h"

#ifdef ENABLE_SEGGER_RTT

#ifdef ENABLE_LOG_SEGGER_RTT
#define LOG(msg, ...) printf("[RTT] " msg, __VA_ARGS__)
#else
#define LOG(...)
#endif

#include "segger_rtt.h"

#include <stdlib.h>

#include "../lib/RTT/RTT/SEGGER_RTT.h"
#include "byte_util.h"

#define BUFFER_UP_FIELD(cb_addr, buf_index, offset) ((cb_addr) + offsetof(SEGGER_RTT_CB, aUp) + (24 * (buf_index)) + (offset))

struct rtt_inst_t
{
    memreg_t *mem;
    uint32_t control_block_addr;
};

rtt_t *rtt_new(memreg_t *mem)
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

    uint32_t addr = memreg_find_data(rtt->mem, x(2000, 0000), 0x10000, (uint8_t *)"SEGGER RTT", 10);
    if (addr == MEMREG_FIND_NOT_FOUND)
        return false;

    LOG("Found SEGGER RTT control block at 0x%08x\n", addr);

    rtt->control_block_addr = addr;

    uint32_t upName = memreg_read(rtt->mem, BUFFER_UP_FIELD(addr, 0, 0));

    char name[32];
    for (size_t i = 0; i < sizeof(name); i++)
    {
        if ((name[i] = memreg_read(rtt->mem, upName + i)) == 0)
            break;
    }

    LOG("Up buffer name: %s\n", name);

    return true;
}

void rtt_flush_buffers(rtt_t *rtt)
{
    if (rtt->control_block_addr == 0)
        return;

    uint32_t cb_addr = rtt->control_block_addr;

    uint32_t bufferAddr = memreg_read(rtt->mem, BUFFER_UP_FIELD(cb_addr, 0, 4));
    uint32_t wrOff = memreg_read(rtt->mem, BUFFER_UP_FIELD(cb_addr, 0, 12));
    uint32_t rdOff = memreg_read(rtt->mem, BUFFER_UP_FIELD(cb_addr, 0, 16));

    if (rdOff == wrOff)
        return;

    uint32_t data_size = wrOff - rdOff;
    char *data = (char *)malloc(data_size + 1);
    data[data_size] = 0;

    for (uint32_t i = rdOff; i < wrOff; i++)
    {
        data[i - rdOff] = memreg_read_byte(rtt->mem, bufferAddr + i);
    }

    LOG("Read %d bytes from RTT buffer: %s\n", wrOff - rdOff, data);

    memreg_write(rtt->mem, BUFFER_UP_FIELD(cb_addr, 0, 16), wrOff, SIZE_WORD);

    // uint32_t upWrOffNew = upWrOff;
    // uint32_t upRdOffNew = upRdOff;

    // memreg_write(rtt->mem, cb_addr + offsetof(SEGGER_RTT_CB, aUp) + offsetof(SEGGER_RTT_BUFFER_UP, RdOff), upRdOff, SIZE_WORD);
}

#else

void pedantic() {}

#endif