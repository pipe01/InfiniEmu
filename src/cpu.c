#include "cpu.h"
#include "arm.h"
#include "byte_util.h"

#include <stdlib.h>
#include <string.h>

cs_insn *insn_at(cpu_t *cpu, uint32_t pc)
{
    pc &= ~1;

    for (size_t i = 0; i < cpu->inst_count; i++)
    {
        if (cpu->inst[i].address == pc)
            return &cpu->inst[i];
    }

    return NULL;
}

cpu_t *cpu_new(uint8_t *program, size_t program_size, memreg_t *mem)
{
    cpu_t *cpu = malloc(sizeof(cpu_t));
    memset(cpu, 0, sizeof(cpu_t));

    cpu->program = program;
    cpu->program_size = program_size;
    cpu->mem = mem;

    csh handle;

    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return NULL;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cpu->inst_count = cs_disasm(handle, program, program_size, 0, 0, &cpu->inst);
    if (cpu->inst_count == 0) {
        fprintf(stderr, "Failed to disassemble program\n");
        return NULL;
    }

    printf("Disassembled %ld instructions\n", cpu->inst_count);

    return cpu;
}

void cpu_reset(cpu_t *cpu)
{
    memset(cpu->core_regs, 0, sizeof(cpu->core_regs));

    cpu->core_regs[ARM_REG_SP] = READ_UINT32(cpu->program, 0);
    cpu->core_regs[ARM_REG_LR] = 0xFFFFFFFF;

    cpu_jump_exception(cpu, ARM_EXCEPTION_RESET);
}

void cpu_step(cpu_t *cpu)
{
    uint32_t pc = cpu->core_regs[ARM_REG_PC];

    printf("PC: 0x%08X\n", pc);

    cs_insn *i = insn_at(cpu, pc);
    if (i == NULL) {
        fprintf(stderr, "Failed to find instruction at 0x%08X\n", cpu->core_regs[ARM_REG_PC]);
        abort();
    }

    uint32_t next = pc + i->size;

    switch (i->id)
    {
    case ARM_INS_LDR:
        break;
    }

    cpu->core_regs[ARM_REG_PC] = next;
}

uint32_t *cpu_reg(cpu_t *cpu, int reg)
{
    return &cpu->core_regs[reg]; // TODO: Bank SP_main and SP_process
}

void cpu_jump_exception(cpu_t *cpu, int exception_num) {
    uint32_t addr = READ_UINT32(cpu->program, exception_num * 4);

    cpu->core_regs[ARM_REG_PC] = addr;
}
