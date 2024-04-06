#pragma once

#include <stdint.h>
#include <capstone/capstone.h>

#include "memory.h"

typedef struct
{
    uint32_t core_regs[ARM_REG_ENDING - 1];
    uint32_t sp_main, sp_process;
    uint32_t xpsr;

    uint8_t *program;
    size_t program_size;

    cs_insn *inst;
    size_t inst_count;
    cs_insn **inst_by_pc;

    memreg_t *mem;
} cpu_t;

cpu_t *cpu_new(uint8_t *program, size_t program_size, memreg_t *mem);
void cpu_reset(cpu_t *cpu);
void cpu_step(cpu_t *cpu);

uint32_t cpu_reg_read(cpu_t *cpu, arm_reg reg);
void cpu_reg_write(cpu_t *cpu, arm_reg reg, uint32_t value);

void cpu_jump_exception(cpu_t *cpu, int exception_num);
