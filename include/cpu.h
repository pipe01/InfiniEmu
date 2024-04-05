#pragma once

#include <stdint.h>
#include <capstone/capstone.h>

typedef struct
{
    uint32_t core_regs[16];
    uint32_t sp_main, sp_process;

    cs_insn *inst;
    size_t inst_count;
} cpu_t;

cpu_t *cpu_new(cs_insn *inst, size_t inst_count);
void cpu_step(cpu_t *cpu);

uint32_t *cpu_reg(cpu_t *cpu, int reg);
