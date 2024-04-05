#pragma once

#include <stdint.h>
#include <capstone/capstone.h>

typedef struct
{
    uint32_t core_regs[16];
    uint32_t sp_main, sp_process;

    uint8_t *program;
    size_t program_size;

    cs_insn *inst;
    size_t inst_count;
} cpu_t;

cpu_t *cpu_new(uint8_t *program, size_t program_size);
void cpu_reset(cpu_t *cpu);
void cpu_step(cpu_t *cpu);

uint32_t *cpu_reg(cpu_t *cpu, int reg);

void cpu_jump_exception(cpu_t *cpu, int exception_num);
