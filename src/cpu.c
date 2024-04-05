#include "cpu.h"

#include <stdlib.h>
#include <string.h>

cs_insn *insn_at(cpu_t *cpu, uint32_t pc)
{
    for (size_t i = 0; i < cpu->inst_count; i++)
    {
        if (cpu->inst[i].address == pc)
            return &cpu->inst[i];
    }

    return NULL;
}

cpu_t *cpu_new(cs_insn *inst, size_t inst_count)
{
    cpu_t *cpu = malloc(sizeof(cpu_t));
    memset(cpu, 0, sizeof(cpu_t));

    cpu->inst = inst;
    cpu->inst_count = inst_count;

    return cpu;
}

void cpu_step(cpu_t *cpu)
{
    cs_insn *i = insn_at(cpu, cpu->core_regs[15]);

    switch (i->id)
    {
    case ARM_INS_ADD:
        break;
    }
}

uint32_t *cpu_reg(cpu_t *cpu, int reg)
{
    return &cpu->core_regs[reg]; // TODO: Bank SP_main and SP_process
}
