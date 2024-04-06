#include "cpu.h"
#include "arm.h"
#include "byte_util.h"
#include "psudocode.h"

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

uint32_t cpu_mem_operand_address(cpu_t *cpu, arm_op_mem op)
{
    uint32_t base = cpu_reg_read(cpu, op.base);

    if (op.index != ARM_REG_INVALID)
    {
        base += cpu_reg_read(cpu, op.index) * op.scale;
    }

    // TODO: Shift

    return base + op.disp;
}

uint32_t cpu_load_operand(cpu_t *cpu, cs_arm_op *op)
{
    uint32_t value;

    switch (op->type)
    {
    case ARM_OP_REG:
        value = cpu_reg_read(cpu, op->reg);
        break;
    case ARM_OP_IMM:
        value = op->imm;
        break;
    case ARM_OP_MEM:
        value = memreg_read(cpu->mem, ALIGN4(cpu_mem_operand_address(cpu, op->mem)));
        break;
    default:
        fprintf(stderr, "Unhandled operand type %d\n", op->type);
        abort();
    }

    if (op->shift.type != ARM_SFT_INVALID)
    {
        // TODO: Implement
        abort();
    }

    return value;
}

uint32_t cpu_store_operand(cpu_t *cpu, cs_arm_op *op, uint32_t value)
{
    printf("store 0x%08X into ", value);

    switch (op->type)
    {
    case ARM_OP_REG:
        cpu_reg_write(cpu, op->reg, value);
        printf("register %d\n", op->reg);
        break;
    case ARM_OP_MEM:
        uint32_t addr = ALIGN4(cpu_mem_operand_address(cpu, op->mem));

        memreg_write(cpu->mem, addr, value);
        printf("memory 0x%08X\n", addr);
        break;
    default:
        fprintf(stderr, "Unhandled operand type %d\n", op->type);
        abort();
    }
}

bool cpu_condition_passed(cpu_t *cpu, cs_insn *i)
{
    arm_cc cc;

    if (i->detail->arm.cc != ARM_CC_INVALID)
        cc = i->detail->arm.cc;
    else
    {
        // TODO: IT blocks
        return true;
    }

    bool result;

    printf("N:%d Z:%d C:%d V:%d\n", IS_SET(cpu->xpsr, APSR_N), IS_SET(cpu->xpsr, APSR_Z), IS_SET(cpu->xpsr, APSR_C), IS_SET(cpu->xpsr, APSR_V));

    switch (cc)
    {
    case ARM_CC_INVALID:
    case ARM_CC_AL:
        return true;

    case ARM_CC_EQ:
        return IS_SET(cpu->xpsr, APSR_Z) != 0;
    case ARM_CC_NE:
        return IS_SET(cpu->xpsr, APSR_Z) == 0;

    case ARM_CC_HS:
        return IS_SET(cpu->xpsr, APSR_C) != 0;
    case ARM_CC_LO:
        return IS_SET(cpu->xpsr, APSR_C) == 0;

    case ARM_CC_MI:
        return IS_SET(cpu->xpsr, APSR_N) != 0;
    case ARM_CC_PL:
        return IS_SET(cpu->xpsr, APSR_N) == 0;

    case ARM_CC_GT:
        return ((IS_SET(cpu->xpsr, APSR_N) != 0) == (IS_SET(cpu->xpsr, APSR_V))) && (IS_SET(cpu->xpsr, APSR_Z) == 0);
    case ARM_CC_LE:
        return ((IS_SET(cpu->xpsr, APSR_N) != 0) != (IS_SET(cpu->xpsr, APSR_V))) || (IS_SET(cpu->xpsr, APSR_Z) != 0);

    case ARM_CC_HI:
        return (IS_SET(cpu->xpsr, APSR_C) != 0) && (IS_SET(cpu->xpsr, APSR_Z) == 0);
    case ARM_CC_LS:
        return (IS_SET(cpu->xpsr, APSR_C) == 0) || (IS_SET(cpu->xpsr, APSR_Z) != 0);

    case ARM_CC_GE:
        return (IS_SET(cpu->xpsr, APSR_N) == 0) == (IS_SET(cpu->xpsr, APSR_V) == 0);
    case ARM_CC_LT:
        return (IS_SET(cpu->xpsr, APSR_N) == 0) != (IS_SET(cpu->xpsr, APSR_V) == 0);

    default:
        fprintf(stderr, "Unhandled condition code %d\n", cc);
        abort();
    }
}

#define UPDATE_N(cpu, value) ((((value) >> 31) == 1) ? SET((cpu)->xpsr, APSR_N) : CLEAR((cpu)->xpsr, APSR_N))
#define UPDATE_Z(cpu, value) (((value) == 0) ? SET((cpu)->xpsr, APSR_Z) : CLEAR((cpu)->xpsr, APSR_Z))
#define UPDATE_C(cpu, carry) ((carry) ? SET((cpu)->xpsr, APSR_C) : CLEAR((cpu)->xpsr, APSR_C))
#define UPDATE_V(cpu, overflow) ((overflow) ? SET((cpu)->xpsr, APSR_V) : CLEAR((cpu)->xpsr, APSR_V))

#define UPDATE_NZ(cpu, inst, value)     \
    if (inst->detail->arm.update_flags) \
    {                                   \
        UPDATE_N((cpu), (value));       \
        UPDATE_Z((cpu), (value));       \
    }

#define UPDATE_NZCV(cpu, inst, value, carry, overflow) \
    if (inst->detail->arm.update_flags)                \
    {                                                  \
        UPDATE_N((cpu), (value));                      \
        UPDATE_Z((cpu), (value));                      \
        UPDATE_C((cpu), (carry));                      \
        UPDATE_V((cpu), (overflow));                   \
    }

cpu_t *cpu_new(uint8_t *program, size_t program_size, memreg_t *mem)
{
    cpu_t *cpu = malloc(sizeof(cpu_t));
    memset(cpu, 0, sizeof(cpu_t));

    cpu->program = program;
    cpu->program_size = program_size;
    cpu->mem = mem;

    csh handle;

    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return NULL;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cpu->inst_count = cs_disasm(handle, program, program_size, 0, 0, &cpu->inst);
    if (cpu->inst_count == 0)
    {
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
    cpu->core_regs[ARM_REG_LR] = x(FFFF, FFFF);

    // cpu->core_regs[ARM_REG_PC] = 0x1d1a8;
    cpu_jump_exception(cpu, ARM_EXCEPTION_RESET);
}

// TODO: Implement
#define BRANCH_WRITE_PC(cpu, pc)            \
    cpu_reg_write((cpu), ARM_REG_PC, (pc)); \
    printf("Branching to 0x%08X\n", (pc));

void cpu_step(cpu_t *cpu)
{
    uint32_t pc = cpu->core_regs[ARM_REG_PC];

    uint32_t op1, op2, value;

    cs_insn *i = insn_at(cpu, pc);
    if (i == NULL)
    {
        fprintf(stderr, "Failed to find instruction at 0x%08X\n", cpu->core_regs[ARM_REG_PC]);
        abort();
    }

    printf("\nPC: 0x%08X %s %s\n", pc, i->mnemonic, i->op_str);

    uint32_t next = pc + i->size;

    if (!cpu_condition_passed(cpu, i))
        goto next_pc;

    bool carry = false;
    bool overflow = false;

    switch (i->id)
    {
    case ARM_INS_B:
        BRANCH_WRITE_PC(cpu, cpu_load_operand(cpu, &i->detail->arm.operands[0]));
        return;

    case ARM_INS_BL:
        cpu_reg_write(cpu, ARM_REG_LR, next | 1);
        BRANCH_WRITE_PC(cpu, cpu_load_operand(cpu, &i->detail->arm.operands[0]));
        return;

    case ARM_INS_LDR:
        value = cpu_load_operand(cpu, &i->detail->arm.operands[1]);

        cpu_store_operand(cpu, &i->detail->arm.operands[0], value);
        break;

    case ARM_INS_STR:
        value = cpu_load_operand(cpu, &i->detail->arm.operands[0]);

        cpu_store_operand(cpu, &i->detail->arm.operands[1], value);
        break;

    case ARM_INS_SUB:
        op1 = cpu_load_operand(cpu, &i->detail->arm.operands[i->detail->arm.op_count == 3 ? 1 : 0]);
        op2 = cpu_load_operand(cpu, &i->detail->arm.operands[i->detail->arm.op_count == 3 ? 2 : 1]);

        carry = true;
        value = AddWithCarry(op1, ~op2, &carry, &overflow);

        printf("sub: 0x%08X - 0x%08X = 0x%08X\n", op1, op2, value);

        cpu_store_operand(cpu, &i->detail->arm.operands[0], value);

        UPDATE_NZCV(cpu, i, value, carry, overflow);
        break;

    default:
        fprintf(stderr, "Unhandled instruction %s %s\n", i->mnemonic, i->op_str);
        abort();
    }

next_pc:
    cpu_set_pc(cpu, next);
}

uint32_t cpu_reg_read(cpu_t *cpu, arm_reg reg)
{
    if (reg == ARM_REG_PC)
        return cpu->core_regs[ARM_REG_PC] + 4;

    return cpu->core_regs[reg]; // TODO: Bank SP_main and SP_process
}

void cpu_reg_write(cpu_t *cpu, arm_reg reg, uint32_t value)
{
    cpu->core_regs[reg] = value; // TODO: Bank SP_main and SP_process
}

void cpu_set_pc(cpu_t *cpu, uint32_t pc)
{
    if (pc & 1 != 1)
    {
        fprintf(stderr, "PC is not aligned\n");
        abort();
    }

    cpu->core_regs[ARM_REG_PC] = pc & ~1;
}

void cpu_jump_exception(cpu_t *cpu, int exception_num)
{
    uint32_t addr = READ_UINT32(cpu->program, exception_num * 4);

    cpu_set_pc(cpu, addr);
}
