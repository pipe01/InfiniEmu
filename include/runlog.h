#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "memory.h"

typedef struct runlog_t runlog_t;

typedef enum __attribute__((packed))
{
    RUNLOG_REG_R0,
    RUNLOG_REG_R1,
    RUNLOG_REG_R2,
    RUNLOG_REG_R3,
    RUNLOG_REG_R4,
    RUNLOG_REG_R5,
    RUNLOG_REG_R6,
    RUNLOG_REG_R7,
    RUNLOG_REG_R8,
    RUNLOG_REG_R9,
    RUNLOG_REG_R10,
    RUNLOG_REG_R11,
    RUNLOG_REG_R12,
    RUNLOG_REG_SP,
    RUNLOG_REG_LR,
    RUNLOG_REG_PC,
    RUNLOG_REG_XPSR,
    RUNLOG_REG_MSP,
    RUNLOG_REG_PSP,

    RUNLOG_REG_MIN = RUNLOG_REG_R0,
    RUNLOG_REG_MAX = RUNLOG_REG_PSP,
} runlog_register_t;

typedef struct
{
    uint32_t core[RUNLOG_REG_MAX + 1];
} runlog_registers_t;

runlog_t *runlog_new(int fd);
void runlog_free(runlog_t *runlog);

void runlog_record_reset(runlog_t *runlog, runlog_registers_t regs);
void runlog_record_load_program(runlog_t *runlog, uint8_t *program, uint32_t size);
void runlog_record_fetch(runlog_t *runlog, uint32_t pc);
void runlog_record_execute(runlog_t *runlog, runlog_registers_t regs);
void runlog_record_memory_load(runlog_t *runlog, uint32_t addr, uint32_t value, runlog_register_t dst, byte_size_t size);
void runlog_record_memory_store(runlog_t *runlog, runlog_register_t src, uint32_t value, uint32_t addr, byte_size_t size);
void runlog_exception_enter(runlog_t *runlog, uint16_t ex_num);
void runlog_exception_exit(runlog_t *runlog, uint16_t ex_num);
