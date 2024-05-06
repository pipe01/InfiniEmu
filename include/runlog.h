#pragma once

#include <assert.h>
#include <stdint.h>

typedef struct runlog_t runlog_t;

typedef enum
{
    RUNLOG_EV_RESET = 0,
    RUNLOG_EV_FETCH_INST = 1,
    RUNLOG_EV_EXECUTE_INST = 2,
    RUNLOG_EV_MEMORY_WRITE = 3, 
} __attribute__ ((__packed__)) runlog_ev_type;
static_assert(sizeof(runlog_ev_type) == 1);

typedef struct
{
    uint32_t core[16]; // R0-R12, SP, LR, PC
    uint32_t xpsr;
    uint32_t msp, psp;
} runlog_registers_t;

typedef struct
{
    runlog_registers_t regs;
} runlog_event_reset;

typedef struct
{
    runlog_registers_t core_regs;
} runlog_event_inst_t;

typedef struct
{
    uint32_t address;
    uint32_t value;
    uint8_t size; // 1, 2 or 4 bytes
} runlog_event_memory_write_t;

typedef struct
{
    runlog_ev_type type;

    union
    {
        runlog_event_reset reset;
        runlog_event_inst_t inst;
        runlog_event_memory_write_t memory_write;
    };
} runlog_event_t;
static_assert(sizeof(runlog_event_t) == 80);

runlog_t *runlog_new(int fd);
void runlog_record(runlog_t *runlog, runlog_event_t event);

static inline void runlog_record_reset(runlog_t *runlog, runlog_registers_t regs)
{
    runlog_record(runlog, (runlog_event_t){
        .type = RUNLOG_EV_RESET,
        .reset = {
            .regs = regs,
        },
    });
}

static inline void runlog_record_inst(runlog_t *runlog, runlog_ev_type type, runlog_registers_t regs)
{
    runlog_record(runlog, (runlog_event_t){
        .type = type,
        .inst = {
            .core_regs = regs,
        },
    });
}
