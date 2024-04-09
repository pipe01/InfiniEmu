#include "cpu.h"
#include "arm.h"
#include "byte_util.h"
#include "psudocode.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// #define LOG_CPU

#ifdef LOG_CPU
#define LOGF(...) printf(__VA_ARGS__)
#else
#define LOGF(...)
#endif

#define UNPREDICTABLE abort()

struct cpu_inst_t
{
    uint32_t core_regs[ARM_REG_ENDING - 1];
    uint32_t sp_main, sp_process;

    uint32_t xpsr, control, faultmask, basepri, primask;

    arm_mode mode;

    uint8_t *program;
    size_t program_size;

    cs_insn *inst;
    size_t inst_count;
    cs_insn **inst_by_pc;

    bool branched;

    memreg_t *mem;
};

static uint32_t cpu_mem_operand_address(cpu_t *cpu, arm_op_mem op)
{
    uint32_t base = cpu_reg_read(cpu, op.base);

    if (op.index != ARM_REG_INVALID)
    {
        base += cpu_reg_read(cpu, op.index) * op.scale;
    }

    assert(op.lshift == 0); // TODO: Shift

    return base + op.disp;
}

static uint32_t cpu_load_operand(cpu_t *cpu, cs_arm_op *op, uint32_t offset, uint32_t *address)
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
        *address = ALIGN4(cpu_mem_operand_address(cpu, op->mem) + offset);
        value = memreg_read(cpu->mem, *address);
        break;
    default:
        fprintf(stderr, "Unhandled operand type %d\n", op->type);
        abort();
    }

    if (op->shift.type != ARM_SFT_INVALID)
    {
        bool carry = false;
        value = Shift_C(value, op->shift.type, op->shift.value, &carry);
    }

    return value;
}

static void cpu_store_operand(cpu_t *cpu, cs_arm_op *op, uint32_t value, size_t size)
{
    LOGF("store 0x%08X into ", value);

    switch (op->type)
    {
    case ARM_OP_REG:
        cpu_reg_write(cpu, op->reg, value);
        LOGF("register %d\n", op->reg);

        if (op->reg == ARM_REG_PC)
            cpu->branched = true;

        break;
    case ARM_OP_MEM:
    {
        uint32_t addr = ALIGN4(cpu_mem_operand_address(cpu, op->mem));
        LOGF("memory 0x%08X\n", addr);

        memreg_write(cpu->mem, addr, value, size);
        break;
    }
    default:
        fprintf(stderr, "Unhandled operand type %d\n", op->type);
        abort();
    }
}

static bool cpu_condition_passed(cpu_t *cpu, cs_insn *i)
{
    arm_cc cc;

    if (i->detail->arm.cc != ARM_CC_INVALID)
        cc = i->detail->arm.cc;
    else
    {
        // TODO: IT blocks
        return true;
    }

    LOGF("N:%d Z:%d C:%d V:%d\n", IS_SET(cpu->xpsr, APSR_N), IS_SET(cpu->xpsr, APSR_Z), IS_SET(cpu->xpsr, APSR_C), IS_SET(cpu->xpsr, APSR_V));

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

static bool cpu_is_privileged(cpu_t *cpu)
{
    return cpu->mode == ARM_MODE_HANDLER || !IS_SET(cpu->control, CONTROL_nPRIV);
}

static int cpu_execution_priority(cpu_t *cpu)
{
    return -1; // TODO: Implement
}

#define UPDATE_N(cpu, value) ((((value) >> 31) == 1) ? SET((cpu)->xpsr, APSR_N) : CLEAR((cpu)->xpsr, APSR_N))
#define UPDATE_Z(cpu, value) (((value) == 0) ? SET((cpu)->xpsr, APSR_Z) : CLEAR((cpu)->xpsr, APSR_Z))
#define UPDATE_C(cpu, carry) ((carry) ? SET((cpu)->xpsr, APSR_C) : CLEAR((cpu)->xpsr, APSR_C))
#define UPDATE_V(cpu, overflow) ((overflow) ? SET((cpu)->xpsr, APSR_V) : CLEAR((cpu)->xpsr, APSR_V))

#define UPDATE_NZ                    \
    if (i->detail->arm.update_flags) \
    {                                \
        UPDATE_N((cpu), (value));    \
        UPDATE_Z((cpu), (value));    \
    }

#define UPDATE_NZC                   \
    if (i->detail->arm.update_flags) \
    {                                \
        UPDATE_N((cpu), (value));    \
        UPDATE_Z((cpu), (value));    \
        UPDATE_C((cpu), (carry));    \
    }

#define UPDATE_NZCV                  \
    if (i->detail->arm.update_flags) \
    {                                \
        UPDATE_N((cpu), (value));    \
        UPDATE_Z((cpu), (value));    \
        UPDATE_C((cpu), (carry));    \
        UPDATE_V((cpu), (overflow)); \
    }

#define WRITEBACK(op_n)                                                     \
    if (detail.writeback)                                           \
    {                                                                       \
        assert(detail.operands[op_n].type == ARM_OP_REG);           \
        cpu_reg_write(cpu, detail.operands[op_n].reg, address);     \
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

    LOGF("Disassembled %ld instructions\n", cpu->inst_count);

    cpu->inst_by_pc = calloc(program_size, sizeof(cs_insn *));

    for (uint32_t i = 0; i < cpu->inst_count; i++)
    {
        cpu->inst_by_pc[cpu->inst[i].address] = &cpu->inst[i];
    }

    return cpu;
}

void cpu_free(cpu_t *cpu)
{
    cs_free(cpu->inst, cpu->inst_count);
    free(cpu->inst_by_pc);
    free(cpu);
}

void cpu_reset(cpu_t *cpu)
{
    memset(cpu->core_regs, 0, sizeof(cpu->core_regs));

    uint32_t sp = READ_UINT32(cpu->program, 0);

    cpu->mode = ARM_MODE_THREAD;
    cpu->core_regs[ARM_REG_SP] = sp;
    cpu->core_regs[ARM_REG_LR] = x(FFFF, FFFF);
    cpu->xpsr = 1 << EPSR_T;
    cpu->control = 0;
    cpu->faultmask = 0;
    cpu->basepri = 0;
    cpu->primask = 0;

    cpu->sp_main = sp;
    cpu->sp_process = sp;

    cpu_jump_exception(cpu, ARM_EXCEPTION_RESET);
}

// TODO: Implement
#define BRANCH_WRITE_PC(cpu, pc)            \
    cpu_reg_write((cpu), ARM_REG_PC, (pc)); \
    LOGF("Branching to 0x%08X\n", (pc));

#define OPERAND_OFF(n, offset) cpu_load_operand(cpu, &i->detail->arm.operands[(n)], (offset), &address)
#define OPERAND(n) OPERAND_OFF(n, 0)
#define OPERAND_REG(n) cpu_reg_read(cpu, i->detail->arm.operands[(n)].reg)

void cpu_step(cpu_t *cpu)
{
    uint32_t pc = cpu->core_regs[ARM_REG_PC];

    uint32_t op0, op1, value, address;

    cs_insn *i = cpu->inst_by_pc[pc & ~1];
    if (i == NULL)
    {
        fprintf(stderr, "Failed to find instruction at 0x%08X\n", cpu->core_regs[ARM_REG_PC]);
        abort();
    }

    cs_arm detail = i->detail->arm;

    LOGF("\nPC: 0x%08X %s %s\n", pc, i->mnemonic, i->op_str);

    uint32_t next = pc + i->size;

    cpu->branched = false;

    // TODO: Ignore condition on certain instructions
    if (!cpu_condition_passed(cpu, i))
        goto next_pc;

    bool carry = false;
    bool overflow = false;

    switch (i->id)
    {
    case ARM_INS_ADC:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        carry = IS_SET(cpu->xpsr, APSR_C);
        value = AddWithCarry(op0, op1, &carry, &overflow);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZCV;
        break;

    case ARM_INS_ADD:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        value = AddWithCarry(op0, op1, &carry, &overflow);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZCV;
        break;

    case ARM_INS_AND:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        value = op0 & op1;

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);
        UPDATE_NZC;
        break;

    case ARM_INS_ASR:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        value = Shift_C(op0, ARM_SFT_ASR, op1, &carry);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_B:
    case ARM_INS_BX:
        assert(detail.op_count == 1);

        BRANCH_WRITE_PC(cpu, OPERAND(0) | 1);
        cpu->branched = true;
        break;

    case ARM_INS_BFC:
    {
        assert(detail.op_count == 3);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_IMM);
        assert(detail.operands[2].type == ARM_OP_IMM);

        op0 = cpu_reg_read(cpu, detail.operands[0].reg);

        uint32_t mask = ((1 << detail.operands[2].imm) - 1) << detail.operands[1].imm;
        value = op0 & ~mask;

        cpu_reg_write(cpu, detail.operands[0].reg, value);
        break;
    }

    case ARM_INS_BFI:
    {
        assert(detail.op_count == 4);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);
        assert(detail.operands[2].type == ARM_OP_IMM);
        assert(detail.operands[3].type == ARM_OP_IMM);

        op0 = cpu_reg_read(cpu, detail.operands[0].reg);
        op1 = cpu_reg_read(cpu, detail.operands[1].reg);

        uint32_t mask = ((1 << detail.operands[3].imm) - 1) << detail.operands[2].imm;

        op0 &= ~mask;
        op0 |= op1 & mask;

        cpu_reg_write(cpu, detail.operands[0].reg, op0);
        break;
    }

    case ARM_INS_BIC:
        assert(detail.operands[0].type == ARM_OP_REG);

        if (detail.op_count == 3)
        {
            assert(detail.operands[1].type == ARM_OP_REG);
            op0 = OPERAND_REG(1);
            op1 = OPERAND(2);
        }
        else
        {
            assert(detail.op_count == 4);
            assert(detail.operands[1].type == ARM_OP_REG);
            assert(detail.operands[2].type == ARM_OP_REG);
            assert(detail.operands[3].type == ARM_OP_IMM);
            op0 = OPERAND_REG(1);
            op1 = OPERAND_REG(2);
        }

        value = op0 & ~op1;
        cpu_reg_write(cpu, detail.operands[0].reg, value);

        // TODO: Update carry
        UPDATE_NZ;
        break;

    case ARM_INS_BL:
    case ARM_INS_BLX:
        assert(detail.op_count == 1);

        cpu_reg_write(cpu, ARM_REG_LR, next | 1);
        BRANCH_WRITE_PC(cpu, OPERAND(0) | 1);
        cpu->branched = true;
        break;

    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
        assert(detail.op_count == 2);
        op0 = OPERAND(0);
        op1 = OPERAND(1);

        if ((op0 == 0) == (i->id == ARM_INS_CBZ))
        {
            BRANCH_WRITE_PC(cpu, op1 | 1);
            cpu->branched = true;
        }
        break;

    case ARM_INS_CLZ:
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);

        op0 = OPERAND_REG(0);
        op1 = OPERAND_REG(1);

        value = op1 == 0 ? 32 : __builtin_clz(op1);
        cpu_reg_write(cpu, detail.operands[0].reg, value);
        break;

    case ARM_INS_CMN:
        assert(detail.update_flags);
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail.operands[0].reg);
        op1 = OPERAND(1);

        value = AddWithCarry(op0, op1, &carry, &overflow);

        UPDATE_NZCV
        break;

    case ARM_INS_CMP:
        assert(detail.update_flags);
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail.operands[0].reg);
        op1 = OPERAND(1);

        carry = true;
        value = AddWithCarry(op0, ~op1, &carry, &overflow);

        UPDATE_NZCV
        break;

    case ARM_INS_CPS:
        if (cpu_is_privileged(cpu))
        {
            if (detail.cps_mode == ARM_CPSMODE_IE)
            {
                if ((detail.cps_flag & ARM_CPSFLAG_I) != 0)
                    CLEAR(cpu->primask, 0);
                if ((detail.cps_flag & ARM_CPSFLAG_F) != 0)
                    CLEAR(cpu->faultmask, 0);
            }
            else if (detail.cps_mode == ARM_CPSMODE_ID)
            {
                if ((detail.cps_flag & ARM_CPSFLAG_I) != 0)
                    SET(cpu->primask, 0);

                if ((detail.cps_flag & ARM_CPSFLAG_F) != 0 && cpu_execution_priority(cpu) > -1)
                    SET(cpu->faultmask, 0);
            }
        }
        break;

    case ARM_INS_DBG:
    case ARM_INS_DMB:
    case ARM_INS_DSB:
    case ARM_INS_ISB:
    case ARM_INS_NOP:
    case ARM_INS_HINT:
    case ARM_INS_IT:
        // Do nothing
        break;

    case ARM_INS_EOR:
        assert(detail.op_count == 2 || detail.op_count == 3);

        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        value = op0 ^ op1;

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);
        UPDATE_NZC
        break;

    case ARM_INS_LDM:
        assert(detail.op_count >= 2);
        assert(detail.operands[0].type == ARM_OP_REG);

        address = cpu_reg_read(cpu, detail.operands[0].reg);

        for (int n = 0; n < detail.op_count - 1; n++)
        {
            value = memreg_read(cpu->mem, address);
            address += 4;

            cpu_reg_write(cpu, detail.operands[n + 1].reg, value);
        }

        // TODO: Check if registers<n> == '0', else don't write back
        if (detail.writeback)
            cpu_reg_write(cpu, detail.operands[0].reg, address);
        break;

    case ARM_INS_LDMDB:
        assert(detail.op_count >= 2);
        assert(detail.operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail.operands[0].reg) - 4 * (detail.op_count - 1);
        address = op0;

        for (int n = 0; n < detail.op_count - 1; n++)
        {
            value = memreg_read(cpu->mem, address);
            address += 4;

            cpu_reg_write(cpu, detail.operands[n + 1].reg, value);
        }

        // TODO: Check if registers<n> == '0', else don't write back
        if (detail.writeback)
            cpu_reg_write(cpu, detail.operands[0].reg, op0);
        break;

    case ARM_INS_LDR:
        assert(detail.op_count == 2 || detail.op_count == 3);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_MEM);

        address = cpu_reg_read(cpu, detail.operands[1].mem.base);

        if (detail.op_count == 3)
        {
            assert(detail.operands[1].mem.disp == 0);
            assert(detail.operands[2].type == ARM_OP_IMM);
            op0 = detail.operands[2].imm;
        }
        else
        {
            op0 = detail.operands[1].mem.disp;
        }

        value = memreg_read(cpu->mem, address + (detail.post_index ? 0 : op0));
        cpu_reg_write(cpu, detail.operands[0].reg, value);

        address += op0;

        if (detail.writeback)
            cpu_reg_write(cpu, detail.operands[1].mem.base, address);

        UPDATE_NZCV;
        break;

    case ARM_INS_LDRB:
        if (detail.op_count == 3)
        {
            assert(detail.operands[2].type == ARM_OP_IMM);
            op0 = detail.operands[2].imm;
        }
        else
        {
            op0 = 0;
        }

        value = OPERAND_OFF(1, op0);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_BYTE);
        break;

    case ARM_INS_LDRD:
        value = cpu_mem_operand_address(cpu, detail.operands[2].mem);

        cpu_store_operand(cpu, &detail.operands[0], memreg_read(cpu->mem, value), SIZE_WORD);
        cpu_store_operand(cpu, &detail.operands[1], memreg_read(cpu->mem, value + 4), SIZE_WORD);
        break;

    case ARM_INS_LDRH:
        op1 = OPERAND(1);
        value = op1 & 0xFFFF;

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);
        break;

    case ARM_INS_LSL:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        value = Shift_C(op0, ARM_SFT_LSL, op1, &carry);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_MOV:
    case ARM_INS_MOVS:
        value = OPERAND(1);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZCV;
        break;

    case ARM_INS_MUL:
        op0 = OPERAND(1);
        op1 = OPERAND(2);

        value = op0 * op1;

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZ
        break;

    case ARM_INS_MVN:
        op1 = OPERAND(1);

        value = ~op1;

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_ORR:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        value = op0 | op1;

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_POP:
        op0 = cpu_reg_read(cpu, ARM_REG_SP);

        cpu_reg_write(cpu, ARM_REG_SP, op0 + 4 * detail.op_count);

        for (int n = 0; n < detail.op_count; n++)
        {
            value = memreg_read(cpu->mem, op0);

            cpu_store_operand(cpu, &detail.operands[n], value, SIZE_WORD);

            op0 += 4;
        }
        break;

    case ARM_INS_PUSH:
        op0 = cpu_reg_read(cpu, ARM_REG_SP) - 4 * detail.op_count;
        cpu_reg_write(cpu, ARM_REG_SP, op0);

        for (size_t n = 0; n < detail.op_count; n++)
        {
            LOGF("Push reg %d\n", detail.operands[n].reg);

            memreg_write(cpu->mem, op0, cpu_load_operand(cpu, &detail.operands[n], 0, &address), SIZE_WORD);

            op0 += 4;
        }
        break;

    case ARM_INS_STR:
        value = OPERAND(0);

        cpu_store_operand(cpu, &detail.operands[1], value, SIZE_WORD);
        break;

    case ARM_INS_STRB:
        op1 = cpu_mem_operand_address(cpu, detail.operands[1].mem);

        value = OPERAND(0);

        memreg_write(cpu->mem, op1, value, SIZE_BYTE);

        if (detail.post_index)
        {
            assert(detail.op_count == 3);

            cpu_reg_write(cpu, detail.operands[1].reg, op1 + detail.operands[2].imm);
        }
        break;

    case ARM_INS_STRD:
        op0 = OPERAND(0);
        op1 = OPERAND(1);
        value = cpu_mem_operand_address(cpu, detail.operands[2].mem);

        cpu_mem_write(cpu, value, op0);
        cpu_mem_write(cpu, value + 4, op1);

        if (detail.writeback)
            abort(); // TODO: Implement
        break;

    case ARM_INS_STRH:
        op1 = cpu_mem_operand_address(cpu, detail.operands[1].mem);

        value = OPERAND(0);

        memreg_write(cpu->mem, op1, value, SIZE_HALFWORD);
        break;

    case ARM_INS_SUB:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        carry = true;
        value = AddWithCarry(op0, ~op1, &carry, &overflow);

        LOGF("sub: 0x%08X - 0x%08X = 0x%08X\n", op0, op1, value);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZCV
        break;

    case ARM_INS_TST:
        op0 = OPERAND(0);
        op1 = OPERAND(1);

        value = op0 & op1;

        UPDATE_NZC
        break;

    case ARM_INS_UBFX:
    {
        op1 = OPERAND(1);
        uint32_t lsb = OPERAND(2);
        uint32_t width = OPERAND(3);

        assert(lsb + width <= 32);

        value = (op1 >> lsb) & ((1 << width) - 1);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);
        break;
    }

    case ARM_INS_UXTB:
        op1 = OPERAND(1);

        cpu_store_operand(cpu, &detail.operands[0], op1 & 0xFF, SIZE_WORD);
        break;

    default:
        fprintf(stderr, "Unhandled instruction %s %s at 0x%08X\n", i->mnemonic, i->op_str, pc);
        // abort();
        exit(1);
    }

next_pc:
    if (!cpu->branched)
        cpu_reg_write(cpu, ARM_REG_PC, next | 1);
}

uint32_t *cpu_get_sp(cpu_t *cpu)
{
    if (IS_SET(cpu->control, CONTROL_SPSEL))
    {
        if (cpu->mode == ARM_MODE_THREAD)
        {
            return &cpu->sp_process;
        }
        else
        {
            UNPREDICTABLE;
            return &cpu->sp_process;
        }
    }
    else
    {
        return &cpu->sp_main;
    }
}

uint32_t cpu_reg_read(cpu_t *cpu, arm_reg reg)
{
    switch (reg)
    {
    case ARM_REG_PC:
        return cpu->core_regs[ARM_REG_PC] + 4;

    case ARM_REG_SP:
        return *cpu_get_sp(cpu);

    default:
        return cpu->core_regs[reg];
    }
}

void cpu_reg_write(cpu_t *cpu, arm_reg reg, uint32_t value)
{
    switch (reg)
    {
    case ARM_REG_PC:
        if ((value & 1) != 1)
        {
            // TODO: Handle better
            fprintf(stderr, "PC is not aligned\n");
            abort();
        }

        cpu->core_regs[ARM_REG_PC] = value & ~1;
        break;

    case ARM_REG_SP:
        *cpu_get_sp(cpu) = value;
        break;

    default:
        cpu->core_regs[reg] = value;
        break;
    }
}

uint32_t cpu_sysreg_read(cpu_t *cpu, arm_sysreg reg)
{
    switch (reg)
    {
    case ARM_SYSREG_XPSR:
    case ARM_SYSREG_APSR:
    case ARM_SYSREG_EPSR:
    case ARM_SYSREG_IPSR:
        return cpu->xpsr;

    case ARM_SYSREG_MSP:
        return cpu->sp_main;

    case ARM_SYSREG_PSP:
        return cpu->sp_process;

    case ARM_SYSREG_CONTROL:
        return cpu->control;

    case ARM_SYSREG_FAULTMASK:
        return cpu->faultmask;

    case ARM_SYSREG_BASEPRI:
        return cpu->basepri;

    case ARM_SYSREG_PRIMASK:
        return cpu->primask;

    default:
        fprintf(stderr, "Unhandled system register %d\n", reg);
        abort();
    }
}

bool cpu_mem_read(cpu_t *cpu, uint32_t addr, uint8_t *value)
{
    if (!memreg_is_mapped(cpu->mem, addr))
        return false;

    *value = memreg_read(cpu->mem, addr);
    return true;
}

bool cpu_mem_write(cpu_t *cpu, uint32_t addr, uint8_t value)
{
    if (!memreg_is_mapped(cpu->mem, addr))
        return false;

    memreg_write(cpu->mem, addr, value, SIZE_BYTE);
    return true;
}

void cpu_jump_exception(cpu_t *cpu, int exception_num)
{
    // TODO: Implement

    uint32_t addr = READ_UINT32(cpu->program, exception_num * 4);

    cpu_reg_write(cpu, ARM_REG_PC, addr);
}
