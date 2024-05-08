#include "arm.h"
#include "byte_util.h"
#include "config.h"
#include "cpu.h"
#include "psudocode.h"

#include "peripherals/peripheral.h"
#include "peripherals/dwt.h"
#include "peripherals/nvic.h"
#include "peripherals/dcb.h"
#include "peripherals/scb.h"
#include "peripherals/scb_fp.h"

#include <assert.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#define LOG(tag, msg, ...) printf("0x%08X: [" tag "] " msg "\n", cpu->core_regs[ARM_REG_PC], __VA_ARGS__)

#ifdef ENABLE_LOG_CPU_EXCEPTIONS
#define LOG_CPU_EX(msg, ...) LOG("CPU_EX", msg, __VA_ARGS__)
#else
#define LOG_CPU_EX(...)
#endif

#ifdef ENABLE_LOG_CPU_INSTRUCTIONS
#define LOG_CPU_INST(msg, ...) LOG("CPU_INST", msg, __VA_ARGS__)
#else
#define LOG_CPU_INST(...)
#endif

#define UNPREDICTABLE abort()

// TODO: Implement
#define BRANCH_WRITE_PC(cpu, pc) cpu_reg_write(cpu, ARM_REG_PC, pc)

#define OPERAND_OFF(n, offset) cpu_load_operand(cpu, &i->detail->arm.operands[(n)], (offset), &address, &carry)
#define OPERAND(n) OPERAND_OFF(n, 0)
#define OPERAND_REG(n) cpu_reg_read(cpu, i->detail->arm.operands[(n)].reg)

#define UPDATE_N(cpu, value) (cpu)->xpsr.apsr_n = ((value) >> 31) == 1
#define UPDATE_Z(cpu, value) (cpu)->xpsr.apsr_z = (value) == 0
#define UPDATE_C(cpu, carry) (cpu)->xpsr.apsr_c = (carry) ? 1 : 0
#define UPDATE_V(cpu, overflow) (cpu)->xpsr.apsr_v = (overflow) ? 1 : 0

#define UPDATE_NZ                 \
    if (detail.update_flags)      \
    {                             \
        UPDATE_N((cpu), (value)); \
        UPDATE_Z((cpu), (value)); \
    }

#define UPDATE_NZC                \
    if (detail.update_flags)      \
    {                             \
        UPDATE_N((cpu), (value)); \
        UPDATE_Z((cpu), (value)); \
        UPDATE_C((cpu), (carry)); \
    }

#define UPDATE_NZCV                  \
    if (detail.update_flags)         \
    {                                \
        UPDATE_N((cpu), (value));    \
        UPDATE_Z((cpu), (value));    \
        UPDATE_C((cpu), (carry));    \
        UPDATE_V((cpu), (overflow)); \
    }

#define WRITEBACK(op_n)                                         \
    if (detail.writeback)                                       \
    {                                                           \
        assert(detail.operands[op_n].type == ARM_OP_REG);       \
        cpu_reg_write(cpu, detail.operands[op_n].reg, address); \
    }

#define MAX_EXECUTING_EXCEPTIONS 64
#define HAS_FP false

typedef struct
{
    arm_exception number;
    int16_t priority;
    bool fixed_priority;
    bool enabled;
    bool fixed_enabled;
    bool active;
    bool pending;
} exception_t;

struct cpu_inst_t
{
    jmp_buf *fault_jmp_buf;
    bool has_fault_jmp;

    runlog_t *runlog;

    uint32_t core_regs[ARM_REG_ENDING - 1];
    uint32_t sp_main, sp_process;

    uint32_t control, faultmask, basepri, primask;
    xPSR_t xpsr;

    arm_cc it_cond[4];
    uint32_t it_block_size, it_block_index;

    arm_mode mode;

    csh cs;
    uint8_t *program;
    size_t program_size;

    cs_insn *inst;
    cs_insn **inst_by_pc;

    size_t exception_count;
    exception_t exceptions[ARM_EXC_EXTERNAL_END + 1];

    size_t executing_exception_count;
    arm_exception executing_exceptions[MAX_EXECUTING_EXCEPTIONS];

    bool branched;

    memreg_t *mem;

    DWT_t *dwt;
    SCB_t *scb;
    SCB_FP_t *scb_fp;
    DCB_t *dcb;
    NVIC_t *nvic;
};

cs_insn *cpu_insn_at(cpu_t *cpu, uint32_t pc);

static inline runlog_registers_t cpu_get_runlog_regs(cpu_t *cpu)
{
    return (runlog_registers_t){
        .core = {
            cpu->core_regs[ARM_REG_R0],
            cpu->core_regs[ARM_REG_R1],
            cpu->core_regs[ARM_REG_R2],
            cpu->core_regs[ARM_REG_R3],
            cpu->core_regs[ARM_REG_R4],
            cpu->core_regs[ARM_REG_R5],
            cpu->core_regs[ARM_REG_R6],
            cpu->core_regs[ARM_REG_R7],
            cpu->core_regs[ARM_REG_R8],
            cpu->core_regs[ARM_REG_R9],
            cpu->core_regs[ARM_REG_R10],
            cpu->core_regs[ARM_REG_R11],
            cpu->core_regs[ARM_REG_R12],
            cpu->core_regs[ARM_REG_SP],
            cpu->core_regs[ARM_REG_LR],
            cpu->core_regs[ARM_REG_PC],
            cpu->xpsr.value,
            cpu->sp_main,
            cpu->sp_process,
        },
    };
}

static inline runlog_register_t runlog_reg(arm_reg arm_reg)
{
    switch (arm_reg)
    {
    case ARM_REG_R0:
        return RUNLOG_REG_R0;
    case ARM_REG_R1:
        return RUNLOG_REG_R1;
    case ARM_REG_R2:
        return RUNLOG_REG_R2;
    case ARM_REG_R3:
        return RUNLOG_REG_R3;
    case ARM_REG_R4:
        return RUNLOG_REG_R4;
    case ARM_REG_R5:
        return RUNLOG_REG_R5;
    case ARM_REG_R6:
        return RUNLOG_REG_R6;
    case ARM_REG_R7:
        return RUNLOG_REG_R7;
    case ARM_REG_R8:
        return RUNLOG_REG_R8;
    case ARM_REG_R9:
        return RUNLOG_REG_R9;
    case ARM_REG_R10:
        return RUNLOG_REG_R10;
    case ARM_REG_R11:
        return RUNLOG_REG_R11;
    case ARM_REG_R12:
        return RUNLOG_REG_R12;
    case ARM_REG_SP:
        return RUNLOG_REG_SP;
    case ARM_REG_LR:
        return RUNLOG_REG_LR;
    case ARM_REG_PC:
        return RUNLOG_REG_PC;
    default:
        abort();
    }
}

static uint32_t cpu_mem_operand_address(cpu_t *cpu, cs_arm_op *op)
{
    uint32_t base = cpu_reg_read(cpu, op->mem.base);

    if (op->mem.index != ARM_REG_INVALID)
    {
        uint32_t offset = cpu_reg_read(cpu, op->mem.index) * op->mem.scale;

        if (op->shift.type != ARM_SFT_INVALID)
        {
            assert(op->shift.type == ARM_SFT_LSL);
            offset <<= op->shift.value;
        }

        base += offset;
    }

    return base + op->mem.disp;
}

static uint32_t cpu_load_operand(cpu_t *cpu, cs_arm_op *op, uint32_t offset, uint32_t *address, bool *carry)
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
    default:
        fprintf(stderr, "Unhandled operand type %d\n", op->type);
        abort();
    }

    if (op->shift.type != ARM_SFT_INVALID)
    {
        value = Shift_C(value, op->shift.type, op->shift.value, carry);
    }

    return value;
}

static void cpu_store_operand(cpu_t *cpu, cs_arm_op *op, uint32_t value, size_t size)
{
    switch (op->type)
    {
    case ARM_OP_REG:
        cpu_reg_write(cpu, op->reg, value);

        if (op->reg == ARM_REG_PC)
            cpu->branched = true;

        break;
    case ARM_OP_MEM:
    {
        uint32_t addr = ALIGN4(cpu_mem_operand_address(cpu, op));

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

    if (cpu->it_block_size > 0)
    {
        cc = cpu->it_cond[cpu->it_block_index++];

        if (cpu->it_block_index == cpu->it_block_size)
            cpu->it_block_size = 0;
    }
    else
    {
        assert(i->detail->arm.cc != ARM_CC_INVALID);

        cc = i->detail->arm.cc;
    }

    switch (cc)
    {
    case ARM_CC_INVALID:
    case ARM_CC_AL:
        return true;

    case ARM_CC_EQ:
        return cpu->xpsr.apsr_z;
    case ARM_CC_NE:
        return !cpu->xpsr.apsr_z;

    case ARM_CC_HS:
        return cpu->xpsr.apsr_c;
    case ARM_CC_LO:
        return !cpu->xpsr.apsr_c;

    case ARM_CC_MI:
        return cpu->xpsr.apsr_n;
    case ARM_CC_PL:
        return !cpu->xpsr.apsr_n;

    case ARM_CC_GT:
        return (cpu->xpsr.apsr_n == cpu->xpsr.apsr_v) && !cpu->xpsr.apsr_z;
    case ARM_CC_LE:
        return (cpu->xpsr.apsr_n != cpu->xpsr.apsr_v) || cpu->xpsr.apsr_z;

    case ARM_CC_HI:
        return cpu->xpsr.apsr_c && !cpu->xpsr.apsr_z;
    case ARM_CC_LS:
        return !cpu->xpsr.apsr_c || cpu->xpsr.apsr_z;

    case ARM_CC_GE:
        return cpu->xpsr.apsr_n == cpu->xpsr.apsr_v;
    case ARM_CC_LT:
        return cpu->xpsr.apsr_n != cpu->xpsr.apsr_v;

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
    int64_t highestpri = 256;
    int64_t boostedpri = 256;

    uint32_t subgroupshift = scb_get_prigroup(cpu->scb);
    uint32_t groupvalue = 2 << subgroupshift;

    int32_t subgroupvalue = 0;

    for (size_t i = 2; i < ARM_EXC_EXTERNAL_END; i++)
    {
        if (cpu->exceptions[i].active)
        {
            if (cpu->exceptions[i].priority < highestpri)
            {
                highestpri = cpu->exceptions[i].priority;

                subgroupvalue = highestpri % groupvalue;
                highestpri -= subgroupvalue;
            }
        }
    }

    if ((cpu->primask & 1) == 1)
    {
        boostedpri = 0;
    }
    else if ((cpu->faultmask & 1) == 1)
    {
        boostedpri = -1;
    }
    else if ((cpu->basepri & 0xFF) != 0)
    {
        boostedpri = cpu->basepri & 0xFF;

        subgroupvalue = boostedpri % groupvalue;
        boostedpri -= subgroupvalue;
    }

    if (boostedpri < highestpri)
        return boostedpri;

    return highestpri;
}

static uint32_t cpu_exception_return_address(cpu_t *cpu, arm_exception ex, bool sync)
{
    uint32_t this_addr = cpu->core_regs[ARM_REG_PC];
    uint32_t next_addr = this_addr + cpu_insn_at(cpu, this_addr)->size;

    switch (ex)
    {
    case ARM_EXC_HARDFAULT:
    case ARM_EXC_BUSFAULT:
    case ARM_EXC_DEBUGMONITOR:
        if (sync)
            return this_addr;
        return next_addr;

    case ARM_EXC_MEMMANAGE:
    case ARM_EXC_USAGEFAULT:
        return this_addr;

    default:
        return next_addr;
    }
}

static void cpu_push_stack(cpu_t *cpu, arm_exception ex, bool sync)
{
    // Copied as closely as possible from the ARMv7-M Architecture Reference Manual's pseudocode at B1.5.6

    uint32_t framesize;
    uint32_t forcealign;

    if (HAS_FP)
    {
        abort();
    }
    else
    {
        framesize = 0x20;
        forcealign = scb_get_ccr(cpu->scb).STKALIGN;
    }

    uint32_t spmask = ~(forcealign << 2);

    uint32_t frameptralign, frameptr;

    if (IS_SET(cpu->control, CONTROL_SPSEL) && cpu->mode == ARM_MODE_THREAD)
    {
        frameptralign = ((cpu->sp_process >> 2) & 1) & forcealign;
        cpu->sp_process = (cpu->sp_process - framesize) & spmask;
        frameptr = cpu->sp_process;
    }
    else
    {
        frameptralign = ((cpu->sp_main >> 2) & 1) & forcealign;
        cpu->sp_main = (cpu->sp_main - framesize) & spmask;
        frameptr = cpu->sp_main;
    }

    memreg_write(cpu->mem, frameptr, cpu->core_regs[ARM_REG_R0], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x4, cpu->core_regs[ARM_REG_R1], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x8, cpu->core_regs[ARM_REG_R2], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0xC, cpu->core_regs[ARM_REG_R3], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x10, cpu->core_regs[ARM_REG_R12], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x14, cpu->core_regs[ARM_REG_LR], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x18, cpu_exception_return_address(cpu, ex, sync), SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x1C, (cpu->xpsr.value & ~(1 << 9)) | (frameptralign << 9), SIZE_WORD);

    if (HAS_FP)
    {
        abort();
    }

    if (cpu->mode == ARM_MODE_HANDLER)
        cpu_reg_write(cpu, ARM_REG_LR, x(FFFF, FFF1));
    else
        cpu_reg_write(cpu, ARM_REG_LR, x(FFFF, FFF9) | (IS_SET(cpu->control, CONTROL_SPSEL) << 2));
}

static void cpu_pop_stack(cpu_t *cpu, uint32_t sp, uint32_t exc_return)
{
    uint32_t framesize;
    uint32_t forcealign;

    if (HAS_FP)
    {
        abort();
    }
    else
    {
        framesize = 0x20;
        forcealign = scb_get_ccr(cpu->scb).STKALIGN;
    }

    cpu->core_regs[ARM_REG_R0] = memreg_read(cpu->mem, sp);
    cpu->core_regs[ARM_REG_R1] = memreg_read(cpu->mem, sp + 0x4);
    cpu->core_regs[ARM_REG_R2] = memreg_read(cpu->mem, sp + 0x8);
    cpu->core_regs[ARM_REG_R3] = memreg_read(cpu->mem, sp + 0xC);
    cpu->core_regs[ARM_REG_R12] = memreg_read(cpu->mem, sp + 0x10);
    cpu->core_regs[ARM_REG_LR] = memreg_read(cpu->mem, sp + 0x14);
    cpu_reg_write(cpu, ARM_REG_PC, memreg_read(cpu->mem, sp + 0x18) | 1);
    uint32_t psr = memreg_read(cpu->mem, sp + 0x1C);

    LOG_CPU_EX("Returning from exception to 0x%08X", cpu->core_regs[ARM_REG_PC]);

    uint32_t spmask = (((psr >> 9) & 1) & forcealign) << 2;

    switch (exc_return & 0xF)
    {
    case 1:
    case 9:
        cpu->sp_main = (cpu->sp_main + framesize) | spmask;
        break;

    case 13:
        cpu->sp_process = (cpu->sp_process + framesize) | spmask;
        break;
    }

    uint32_t new_psr = 0;
    new_psr |= (psr >> 27) << 27;
    new_psr |= psr & IPSR_MASK;
    new_psr |= psr & 0x700FC00;
    cpu->xpsr.value = new_psr;
}

static void cpu_exception_taken(cpu_t *cpu, arm_exception ex)
{
    uint32_t tmp;

    tmp = memreg_read(cpu->mem, 4 * ex);
    cpu->core_regs[ARM_REG_PC] = tmp & ~1;
    cpu->branched = true;

    if ((tmp & 1) != 1)
        abort();

    cpu->mode = ARM_MODE_HANDLER;

    cpu->xpsr.value &= ~IPSR_MASK;
    cpu->xpsr.value |= ex & IPSR_MASK;
    // TODO: Clear EPSR IT

    cpu->control &= ~(1 << CONTROL_FPCA);
    cpu->control &= ~(1 << CONTROL_SPSEL);

    cpu->exceptions[ex].active = true;

    // TODO: SCS_UpdateStatusRegs
}

static void cpu_exception_entry(cpu_t *cpu, arm_exception ex, bool sync)
{
    LOG_CPU_EX("Entering exception %d from 0x%08X", ex, cpu->core_regs[ARM_REG_PC]);

    cpu_push_stack(cpu, ex, sync);
    cpu_exception_taken(cpu, ex);

    cpu->exceptions[ex].pending = false;
}

static void cpu_exception_return(cpu_t *cpu, uint32_t exc_return)
{
    assert(cpu->mode == ARM_MODE_HANDLER);

    arm_exception returning_exception_number = cpu->xpsr.ipsr;
    uint32_t nested_activation = 0;

    for (size_t i = 0; i < cpu->exception_count; i++)
    {
        if (cpu->exceptions[i].active)
            nested_activation++;
    }

    assert(cpu->exceptions[returning_exception_number].active);

    uint32_t frameptr;

    switch (exc_return & 0xF)
    {
    case 1:
        frameptr = cpu->sp_main;
        cpu->mode = ARM_MODE_HANDLER;
        cpu->control &= ~(1 << CONTROL_SPSEL);
        break;

    case 9:
        // TODO: Check NestedActivation and CCR.NONBASETHRDENA

        frameptr = cpu->sp_main;
        cpu->mode = ARM_MODE_THREAD;
        cpu->control &= ~(1 << CONTROL_SPSEL);
        break;

    case 13:
        // TODO: Check NestedActivation and CCR.NONBASETHRDENA

        frameptr = cpu->sp_process;
        cpu->mode = ARM_MODE_THREAD;
        cpu->control |= 1 << CONTROL_SPSEL;
        break;

    default:
        abort();
        break;
    }

    cpu->exceptions[returning_exception_number].active = false;

    if (cpu->xpsr.ipsr != 2)
        cpu->faultmask = 0;

    cpu_pop_stack(cpu, frameptr, exc_return);
}

void cpu_set_fault_jmp(cpu_t *cpu, jmp_buf *buf)
{
    cpu->fault_jmp_buf = buf;
    cpu->has_fault_jmp = true;
}

void cpu_clear_fault_jmp(cpu_t *cpu)
{
    cpu->has_fault_jmp = false;
}

static void cpu_do_fault_jmp(cpu_t *cpu)
{
    if (cpu->has_fault_jmp)
        longjmp(*cpu->fault_jmp_buf, 1);
    else
        abort();
}

void cpu_set_runlog(cpu_t *cpu, runlog_t *runlog)
{
    cpu->runlog = runlog;
}

void cpu_exception_set_pending(cpu_t *cpu, arm_exception ex)
{
    cpu->exceptions[ex].pending = true;

    LOG_CPU_EX("Exception %d is now pending", ex);
}

void cpu_exception_clear_pending(cpu_t *cpu, arm_exception ex)
{
    cpu->exceptions[ex].pending = false;

    LOG_CPU_EX("Exception %d is no longer pending", ex);
}

bool cpu_exception_is_pending(cpu_t *cpu, arm_exception ex)
{
    return cpu->exceptions[ex].pending;
}

void cpu_exception_set_enabled(cpu_t *cpu, arm_exception ex, bool enabled)
{
    if (cpu->exceptions[ex].fixed_enabled)
        abort();

    cpu->exceptions[ex].enabled = enabled;
}

static arm_exception cpu_exception_get_pending(cpu_t *cpu, int16_t current_priority)
{
    int16_t min_priority = ARM_MAX_PRIORITY;
    arm_exception min_ex = 0;

    for (arm_exception i = 1; i < cpu->exception_count; i++)
    {
        exception_t *ex = &cpu->exceptions[i];

        if (ex->enabled && ex->pending && !ex->active && ex->priority <= min_priority)
        {
            min_priority = ex->priority;
            min_ex = i;
        }
    }

    if (min_priority >= current_priority)
        return 0;

    return min_ex;
}

static void cpu_do_load(cpu_t *cpu, cs_arm *detail, byte_size_t size, uint32_t alignment, bool sign_extend)
{
    assert(detail->op_count == 2 || detail->op_count == 3);
    assert(detail->operands[0].type == ARM_OP_REG);
    assert(detail->operands[1].type == ARM_OP_MEM);
    assert(size == 1 || size == 2 || size == 4);

    uint32_t address = cpu_reg_read(cpu, detail->operands[1].mem.base);
    uint32_t offset;

    if (detail->op_count == 3)
    {
        assert(detail->operands[1].mem.disp == 0);
        assert(detail->operands[2].type == ARM_OP_IMM);
        offset = detail->operands[2].imm;
    }
    else
    {
        offset = detail->operands[1].mem.disp;

        if (detail->operands[1].mem.index != ARM_REG_INVALID)
            offset += (cpu_reg_read(cpu, detail->operands[1].mem.index) * detail->operands[1].mem.scale) << detail->operands[1].shift.value;
    }

    uint32_t mask = size == 1   ? 0xFF
                    : size == 2 ? 0xFFFF
                                : x(FFFF, FFFF);

    // TODO: Why do we need to align the address?
    uint32_t offsetAddr = (address & alignment) + (detail->post_index ? 0 : offset);
    uint32_t value = memreg_read(cpu->mem, offsetAddr) & mask;

    if (sign_extend)
    {
        bool sign_bit = (value & ((mask + 1) >> 1)) != 0;

        if (sign_bit)
        {
            switch (size)
            {
            case SIZE_BYTE:
                value = (uint32_t)(int8_t)value;
                break;

            case SIZE_HALFWORD:
                value = (uint32_t)(int16_t)value;
                break;

            case SIZE_WORD:
                // Do nothing
                break;
            }
        }
    }

    if (cpu->runlog)
    {
        runlog_record_memory_load(cpu->runlog, offsetAddr, value, runlog_reg(detail->operands[0].reg), size);
    }

    cpu_reg_write(cpu, detail->operands[0].reg, value);

    if (detail->writeback)
    {
        address += offset;

        cpu_reg_write(cpu, detail->operands[1].mem.base, address);
    }
}

static void cpu_do_store(cpu_t *cpu, cs_arm *detail, byte_size_t size, bool dual)
{
    uint32_t base, offset_addr;
    bool is_long;

    uint8_t op_count = detail->op_count;
    cs_arm_op *mem_op;

    if (dual)
    {
        assert(size == SIZE_WORD);
        assert(op_count == 3 || op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_MEM);
        base = offset_addr = cpu_reg_read(cpu, detail->operands[2].mem.base);
        is_long = op_count == 4;
        mem_op = &detail->operands[2];
    }
    else
    {
        assert(op_count == 2 || op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_MEM);
        base = offset_addr = cpu_reg_read(cpu, detail->operands[1].mem.base);
        is_long = op_count == 3;
        mem_op = &detail->operands[1];
    }

    if (is_long)
    {
        assert(detail->operands[op_count - 1].type == ARM_OP_IMM);
        offset_addr += detail->operands[op_count - 1].imm;
    }
    else
    {
        offset_addr += mem_op->mem.disp;

        if (mem_op->mem.index != ARM_REG_INVALID)
        {
            if (mem_op->shift.type != ARM_SFT_INVALID)
                assert(mem_op->shift.type == ARM_SFT_LSL);

            offset_addr += (cpu_reg_read(cpu, mem_op->mem.index) << mem_op->shift.value) * mem_op->mem.scale;
        }
    }

    uint32_t value = cpu_reg_read(cpu, detail->operands[0].reg) & size_mask(size);
    uint32_t address = detail->post_index ? base : offset_addr;

    memreg_write(cpu->mem, address, value, size);

    if (cpu->runlog)
    {
        runlog_record_memory_store(cpu->runlog, runlog_reg(detail->operands[0].reg), value, address, size);
    }

    if (dual)
    {
        value = cpu_reg_read(cpu, detail->operands[1].reg);
        memreg_write(cpu->mem, address + 4, value, size);
    }

    if (detail->writeback)
        cpu_reg_write(cpu, mem_op->mem.base, offset_addr);
}

static void cpu_add_arm_memregs(cpu_t *cpu, size_t priority_bits)
{
    memreg_t *first = memreg_find_last(cpu->mem);
    memreg_t *last = first;

    NEW_PERIPH(cpu, DWT, dwt, dwt, x(E000, 1000), 0x1000);
    NEW_PERIPH(cpu, SCB, scb, scb, x(E000, ED00), 0x90, cpu);
    NEW_PERIPH(cpu, DCB, dcb, dcb, x(E000, EDF0), 0x110);
    NEW_PERIPH(cpu, SCB_FP, scb_fp, scb_fp, x(E000, EF00), 0x90, cpu);
    NEW_PERIPH(cpu, NVIC, nvic, nvic, x(E000, E100), 0xBFF, cpu, priority_bits);
}

static void cpu_do_stmdb(cpu_t *cpu, arm_reg base_reg, bool writeback, cs_arm_op *reg_operands, uint8_t reg_count)
{
    uint32_t address = cpu_reg_read(cpu, base_reg) - 4 * reg_count;

    if (writeback)
        cpu_reg_write(cpu, base_reg, address);

    for (size_t i = 0; i < reg_count; i++)
    {
        assert(reg_operands[i].type == ARM_OP_REG);

        memreg_write(cpu->mem, address, cpu_reg_read(cpu, reg_operands[i].reg), SIZE_WORD);

        address += 4;
    }
}

cpu_t *cpu_new(uint8_t *program, size_t program_size, memreg_t *mem, size_t max_external_interrupts, size_t priority_bits)
{
    cpu_t *cpu = malloc(sizeof(cpu_t));
    memset(cpu, 0, sizeof(cpu_t));

    cpu->program = program;
    cpu->program_size = program_size;
    cpu->mem = mem;
    cpu->exception_count = 16 + max_external_interrupts;

    cpu_add_arm_memregs(cpu, priority_bits);

    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS, &cpu->cs) != CS_ERR_OK)
    {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return NULL;
    }

    cs_option(cpu->cs, CS_OPT_DETAIL, CS_OPT_ON);
    // cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cpu->inst_by_pc = calloc(program_size, sizeof(cs_insn *));

    return cpu;
}

void cpu_free(cpu_t *cpu)
{
    for (size_t i = 0; i < cpu->program_size; i++)
    {
        cs_insn *ins = cpu->inst_by_pc[i];

        if (ins)
            cs_free(cpu->inst_by_pc[i], 1);
    }

    free(cpu->inst_by_pc);
    free(cpu);
}

void cpu_reset(cpu_t *cpu)
{
    memset(cpu->core_regs, 0, sizeof(cpu->core_regs));

    cpu->mode = ARM_MODE_THREAD;
    cpu->primask = 0;
    cpu->faultmask = 0;
    cpu->basepri = 0;
    cpu->control = 0;

    cpu->sp_main = READ_UINT32(cpu->program, 0) & x(FFFF, FFFC);
    cpu->sp_process = 0;

    cpu->core_regs[ARM_REG_LR] = x(FFFF, FFFF);
    cpu->xpsr.value = 0;
    cpu->xpsr.epsr_t = 1;

    memset(cpu->exceptions, 0, sizeof(cpu->exceptions));

    for (size_t n = 1; n < cpu->exception_count; n++)
    {
        cpu->exceptions[n].number = n;
    }

    cpu->exceptions[ARM_EXC_RESET].priority = -3;
    cpu->exceptions[ARM_EXC_RESET].fixed_priority = true;
    cpu->exceptions[ARM_EXC_RESET].enabled = true;
    cpu->exceptions[ARM_EXC_RESET].fixed_enabled = true;

    cpu->exceptions[ARM_EXC_NMI].priority = -2;
    cpu->exceptions[ARM_EXC_NMI].fixed_priority = true;
    cpu->exceptions[ARM_EXC_NMI].enabled = true;
    cpu->exceptions[ARM_EXC_NMI].fixed_enabled = true;

    cpu->exceptions[ARM_EXC_HARDFAULT].priority = -1;
    cpu->exceptions[ARM_EXC_HARDFAULT].fixed_priority = true;
    cpu->exceptions[ARM_EXC_HARDFAULT].enabled = true;
    cpu->exceptions[ARM_EXC_HARDFAULT].fixed_enabled = true;

    cpu->exceptions[ARM_EXC_MEMMANAGE].enabled = true;
    cpu->exceptions[ARM_EXC_BUSFAULT].enabled = true;
    cpu->exceptions[ARM_EXC_USAGEFAULT].enabled = true;

    cpu->exceptions[ARM_EXC_SVC].enabled = true;
    cpu->exceptions[ARM_EXC_SVC].fixed_enabled = true;
    cpu->exceptions[ARM_EXC_PENDSV].enabled = true;
    cpu->exceptions[ARM_EXC_PENDSV].fixed_enabled = true;
    cpu->exceptions[ARM_EXC_SYSTICK].enabled = true;
    cpu->exceptions[ARM_EXC_SYSTICK].fixed_enabled = true;

    cpu_jump_exception(cpu, ARM_EXC_RESET);

    if (cpu->runlog)
    {
        runlog_record_reset(cpu->runlog, cpu_get_runlog_regs(cpu));
    }
}

cs_insn *cpu_insn_at(cpu_t *cpu, uint32_t pc)
{
    assert((pc & x(FFFF, FFFE)) == pc); // Check that PC is aligned

    if (!cpu->inst_by_pc[pc])
    {
        size_t n = cs_disasm(cpu->cs, &cpu->program[pc], cpu->program_size - pc, pc, 1, &cpu->inst_by_pc[pc]);

        if (n == 0)
        {
            fprintf(stderr, "Failed to disassemble code at 0x%08X\n", pc);
            abort();
        }
    }

    return cpu->inst_by_pc[pc];
}

void cpu_step(cpu_t *cpu)
{
    dwt_increment_cycle(cpu->dwt);

    arm_exception pending;

    uint32_t pc = cpu->core_regs[ARM_REG_PC];

    uint32_t op0, op1, value, address;

    cs_insn *i = cpu_insn_at(cpu, pc);
    if (i == NULL)
    {
        fprintf(stderr, "Failed to find instruction at 0x%08X\n", cpu->core_regs[ARM_REG_PC]);
        abort();
    }

    if (cpu->runlog)
    {
        runlog_record_fetch(cpu->runlog, pc);
    }

    cs_arm detail = i->detail->arm;

    LOG_CPU_INST("%s %s", i->mnemonic, i->op_str);

    uint32_t next = pc + i->size;

    cpu->branched = false;

    // TODO: Ignore condition on certain instructions
    if (i->id != ARM_INS_IT && !cpu_condition_passed(cpu, i))
        goto next_pc;

    bool carry = false;
    bool overflow = false;

    switch (i->id)
    {
    case ARM_INS_ADC:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        carry = cpu->xpsr.apsr_c;
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

    case ARM_INS_ADR:
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_IMM);

        value = cpu_reg_read(cpu, ARM_REG_PC) + detail.operands[1].imm;

        cpu_reg_write(cpu, detail.operands[0].reg, value);
        break;

    case ARM_INS_AND:
        carry = cpu->xpsr.apsr_c;

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
        break;

    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
        assert(detail.op_count == 2);
        op0 = OPERAND(0);
        op1 = OPERAND(1);

        if ((op0 == 0) == (i->id == ARM_INS_CBZ))
            BRANCH_WRITE_PC(cpu, op1 | 1);
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

    case ARM_INS_IT:
    {
        assert(i->size == 2);
        assert(i->bytes[1] == 0xBF);

        union
        {
            struct
            {
                unsigned int mask0 : 1;
                unsigned int mask1 : 1;
                unsigned int mask2 : 1;
                unsigned int mask3 : 1;
                unsigned int firstcond0 : 1;
                unsigned int firstcond : 3;
            } __attribute__((packed));
            uint8_t value;
        } it;
        static_assert(sizeof(it) == 1, "IT block must be a single byte");

        it.value = i->bytes[0];

        arm_cc cond = detail.cc;
        arm_cc invcond = invert_cc(cond);

        cpu->it_block_index = 0;
        cpu->it_cond[0] = cond;

        if (it.mask0 == 1)
        {
            cpu->it_block_size = 4;
            cpu->it_cond[1] = it.mask3 == it.firstcond0 ? cond : invcond;
            cpu->it_cond[2] = it.mask2 == it.firstcond0 ? cond : invcond;
            cpu->it_cond[3] = it.mask1 == it.firstcond0 ? cond : invcond;
        }
        else if (it.mask1 == 1)
        {
            cpu->it_block_size = 3;
            cpu->it_cond[1] = it.mask3 == it.firstcond0 ? cond : invcond;
            cpu->it_cond[2] = it.mask2 == it.firstcond0 ? cond : invcond;
        }
        else if (it.mask2 == 1)
        {
            cpu->it_block_size = 2;
            cpu->it_cond[1] = it.mask3 == it.firstcond0 ? cond : invcond;
        }
        else if (it.mask3 == 1)
        {
            cpu->it_block_size = 1;
        }
        else
        {
            abort();
        }

        break;
    }

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
    case ARM_INS_LDREX:
        cpu_do_load(cpu, &detail, SIZE_WORD, x(FFFF, FFFF) << 2, false);
        break;

    case ARM_INS_LDRB:
        cpu_do_load(cpu, &detail, SIZE_BYTE, x(FFFF, FFFF), false);
        break;

    case ARM_INS_LDRSB:
        cpu_do_load(cpu, &detail, SIZE_BYTE, x(FFFF, FFFF), true);
        break;

    case ARM_INS_LDRD:
        value = cpu_mem_operand_address(cpu, &detail.operands[2]);

        cpu_store_operand(cpu, &detail.operands[0], memreg_read(cpu->mem, value), SIZE_WORD);
        cpu_store_operand(cpu, &detail.operands[1], memreg_read(cpu->mem, value + 4), SIZE_WORD);
        break;

    case ARM_INS_LDRH:
        cpu_do_load(cpu, &detail, SIZE_HALFWORD, x(FFFF, FFFF) << 1, false);
        break;

    case ARM_INS_LDRSH:
        cpu_do_load(cpu, &detail, SIZE_HALFWORD, x(FFFF, FFFF) << 1, true);
        break;

    case ARM_INS_LSL:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        value = Shift_C(op0, ARM_SFT_LSL, op1, &carry);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_LSR:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        value = Shift_C(op0, ARM_SFT_LSR, op1, &carry);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_MLA:
        assert(detail.op_count == 4);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);
        assert(detail.operands[2].type == ARM_OP_REG);
        assert(detail.operands[3].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail.operands[1].reg);
        op1 = cpu_reg_read(cpu, detail.operands[2].reg);
        value = cpu_reg_read(cpu, detail.operands[3].reg);
        value += op0 * op1;

        cpu_reg_write(cpu, detail.operands[0].reg, value);

        UPDATE_NZ
        break;

    case ARM_INS_MLS:
    {
        assert(detail.op_count == 4);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);
        assert(detail.operands[2].type == ARM_OP_REG);
        assert(detail.operands[3].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail.operands[1].reg);
        op1 = cpu_reg_read(cpu, detail.operands[2].reg);
        uint32_t addend = cpu_reg_read(cpu, detail.operands[3].reg);

        value = addend - op0 * op1;

        cpu_reg_write(cpu, detail.operands[0].reg, value);
        break;
    }

    case ARM_INS_MOV:
    case ARM_INS_MOVS:
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_REG);

        value = OPERAND(1);

        cpu_reg_write(cpu, detail.operands[0].reg, value);

        UPDATE_NZ; // FIXME: Carry should also be set sometimes but it seems like Capstone doesn't expose it
        break;

    case ARM_INS_MRS:
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_SYSREG);

        value = cpu_sysreg_read(cpu, detail.operands[1].reg);

        cpu_reg_write(cpu, detail.operands[0].reg, value);
        break;

    case ARM_INS_MSR:
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_SYSREG);
        assert(detail.operands[1].type == ARM_OP_REG);

        value = cpu_reg_read(cpu, detail.operands[1].reg);

        cpu_sysreg_write(cpu, detail.operands[0].reg, value);
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
        cpu_do_stmdb(cpu, ARM_REG_SP, true, &detail.operands[0], detail.op_count);
        break;

    case ARM_INS_RSB:
        assert(detail.op_count == 3);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);

        op1 = cpu_reg_read(cpu, detail.operands[1].reg);

        carry = true;
        value = AddWithCarry(~op1, detail.operands[2].imm, &carry, &overflow);

        cpu_reg_write(cpu, detail.operands[0].reg, value);

        UPDATE_NZCV
        break;

    case ARM_INS_SDIV: // TODO: Perform signed division
    case ARM_INS_UDIV:
        assert(detail.op_count == 2 || detail.op_count == 3);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);
        assert(detail.op_count < 3 || detail.operands[2].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail.operands[detail.op_count == 3 ? 1 : 0].reg);
        op1 = cpu_reg_read(cpu, detail.operands[detail.op_count == 3 ? 2 : 1].reg);

        // TODO: Exception if op1 is zero
        assert(op1 != 0);

        value = div(op0, op1).quot;

        cpu_reg_write(cpu, detail.operands[0].reg, value);
        break;

    case ARM_INS_SMULL:
        assert(detail.op_count == 4);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);
        assert(detail.operands[2].type == ARM_OP_REG);
        assert(detail.operands[3].type == ARM_OP_REG);

        uint64_t result = (int64_t)(int32_t)cpu_reg_read(cpu, detail.operands[2].reg) * (int64_t)(int32_t)cpu_reg_read(cpu, detail.operands[3].reg);

        cpu_reg_write(cpu, detail.operands[0].reg, result & x(FFFF, FFFF));
        cpu_reg_write(cpu, detail.operands[1].reg, result >> 32);
        break;

    case ARM_INS_STM:
        assert(detail.op_count >= 2);
        assert(detail.operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail.operands[0].reg);

        for (size_t n = 0; n < detail.op_count; n++)
        {
            assert(detail.operands[n].type == ARM_OP_REG);

            memreg_write(cpu->mem, op0, cpu_reg_read(cpu, detail.operands[n].reg), SIZE_WORD);

            op0 += 4;
        }

        if (detail.writeback)
            cpu_reg_write(cpu, detail.operands[0].reg, op0);
        break;

    case ARM_INS_STR:
        cpu_do_store(cpu, &detail, SIZE_WORD, false);
        break;

    case ARM_INS_STRB:
        cpu_do_store(cpu, &detail, SIZE_BYTE, false);
        break;

    case ARM_INS_STRD:
        cpu_do_store(cpu, &detail, SIZE_WORD, true);
        break;

    case ARM_INS_STREX:
        assert(detail.op_count == 3);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);
        assert(detail.operands[2].type == ARM_OP_MEM);

        op0 = cpu_mem_operand_address(cpu, &detail.operands[2]);

        cpu_reg_write(cpu, detail.operands[0].reg, 0);
        memreg_write(cpu->mem, op0, cpu_reg_read(cpu, detail.operands[1].reg), SIZE_WORD);
        break;

    case ARM_INS_STRH:
        cpu_do_store(cpu, &detail, SIZE_HALFWORD, false);
        break;

    case ARM_INS_STMDB:
        cpu_do_stmdb(cpu, detail.operands[0].reg, detail.writeback, &detail.operands[1], detail.op_count - 1);
        break;

    case ARM_INS_SUB:
        op0 = OPERAND(detail.op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail.op_count == 3 ? 2 : 1);

        carry = true;
        value = AddWithCarry(op0, ~op1, &carry, &overflow);

        cpu_store_operand(cpu, &detail.operands[0], value, SIZE_WORD);

        UPDATE_NZCV
        break;

    case ARM_INS_SVC:
        cpu_exception_set_pending(cpu, ARM_EXC_SVC);
        break;

    case ARM_INS_SXTB:
        assert(detail.op_count == 2); // TODO: Handle rotation case
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);

        op1 = cpu_reg_read(cpu, detail.operands[1].reg);
        value = (uint32_t)(int8_t)(op1 & 0xFF);
        break;

    case ARM_INS_SXTH:
        assert(detail.op_count == 2); // TODO: Handle rotation case
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);

        op1 = cpu_reg_read(cpu, detail.operands[1].reg);
        value = (uint32_t)(int16_t)(op1 & 0xFFFF);
        break;

    case ARM_INS_TBB:
    case ARM_INS_TBH:
        assert(detail.op_count == 1);
        assert(detail.operands[0].type == ARM_OP_MEM);

        op0 = cpu_mem_operand_address(cpu, &detail.operands[0]);
        value = memreg_read(cpu->mem, op0) & (i->id == ARM_INS_TBB ? 0xFF : 0xFFFF);

        cpu_reg_write(cpu, ARM_REG_PC, (cpu_reg_read(cpu, ARM_REG_PC) + value * 2) | 1);
        break;

    case ARM_INS_TEQ:
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail.operands[0].reg);
        op1 = OPERAND(1);

        value = op0 ^ op1;

        UPDATE_NZC
        break;

    case ARM_INS_TST:
        assert(detail.op_count == 2);
        assert(detail.operands[1].shift.value == 0);

        op0 = OPERAND(0);
        op1 = OPERAND(1);

        value = op0 & op1;

        UPDATE_NZ
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

    case ARM_INS_USAT:
        assert(detail.op_count == 3);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_IMM);
        assert(detail.operands[2].type == ARM_OP_REG);

        op0 = detail.operands[1].imm;
        op1 = OPERAND(2);

        bool saturated = UnsignedSatQ(op1, op0, &value);
        cpu_reg_write(cpu, detail.operands[0].reg, value);

        if (saturated)
            cpu->xpsr.apsr_q = 1;
        break;

    case ARM_INS_UXTB:
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);

        op1 = cpu_reg_read(cpu, detail.operands[1].reg);

        cpu_reg_write(cpu, detail.operands[0].reg, op1 & 0xFF);
        break;

    case ARM_INS_UXTH:
        assert(detail.op_count == 2);
        assert(detail.operands[0].type == ARM_OP_REG);
        assert(detail.operands[1].type == ARM_OP_REG);

        op1 = cpu_reg_read(cpu, detail.operands[1].reg);

        cpu_reg_write(cpu, detail.operands[0].reg, op1 & 0xFFFF);
        break;

    case ARM_INS_VLDMIA:
    case ARM_INS_VMRS:
    case ARM_INS_VMSR:
    case ARM_INS_VSTMDB:
        LOG_CPU_INST("Implement instruction %d\n", i->id);
        // TODO: Implement
        break;

    default:
        fprintf(stderr, "Unhandled instruction %s %s at 0x%08X\n", i->mnemonic, i->op_str, pc);
        cpu_do_fault_jmp(cpu);
        abort();
    }

next_pc:
    if (cpu->runlog)
    {
        runlog_record_execute(cpu->runlog, cpu_get_runlog_regs(cpu));
    }

    pending = cpu_exception_get_pending(cpu, cpu_execution_priority(cpu));
    if (pending != 0)
    {
        cpu_exception_entry(cpu, pending, false);
    }

    if (!cpu->branched)
    {
        cpu_reg_write(cpu, ARM_REG_PC, next | 1);
    }
    else
    {
        LOG_CPU_INST("Branched from 0x%08X to 0x%08X", pc, cpu->core_regs[ARM_REG_PC]);
    }
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
        if (cpu->mode == ARM_MODE_HANDLER && (value & x(F000, 0000)) != 0)
        {
            // TODO: Only do this on certain instructions
            cpu_exception_return(cpu, value & x(0FFF, FFFF));
            break;
        }

        if ((value & 1) != 1)
        {
            // TODO: Handle better
            fprintf(stderr, "PC is not aligned\n");
            cpu_do_fault_jmp(cpu);
            abort();
        }

        cpu->core_regs[ARM_REG_PC] = value & ~1;
        cpu->branched = true;
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
        return cpu->xpsr.value;

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

void cpu_sysreg_write(cpu_t *cpu, arm_sysreg reg, uint32_t value)
{
    switch (reg)
    {
    case ARM_SYSREG_XPSR:
    case ARM_SYSREG_APSR:
    case ARM_SYSREG_EPSR:
    case ARM_SYSREG_IPSR:
        cpu->xpsr.value = value;
        break;

    case ARM_SYSREG_MSP:
        cpu->sp_main = value;
        break;

    case ARM_SYSREG_PSP:
        cpu->sp_process = value;
        break;

    case ARM_SYSREG_CONTROL:
        cpu->control = value;
        break;

    case ARM_SYSREG_FAULTMASK:
        cpu->faultmask = value;
        break;

    case ARM_SYSREG_BASEPRI:
        cpu->basepri = value;
        break;

    case ARM_SYSREG_PRIMASK:
        cpu->primask = value;
        break;

    default:
        fprintf(stderr, "Unhandled system register %d\n", reg);
        abort();
    }
}

memreg_t *cpu_mem(cpu_t *cpu)
{
    return cpu->mem;
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

void cpu_jump_exception(cpu_t *cpu, arm_exception ex)
{
    cpu_reg_write(cpu, ARM_REG_PC, READ_UINT32(cpu->program, ex * 4));
}

int16_t cpu_get_exception_priority(cpu_t *cpu, arm_exception ex)
{
    return cpu->exceptions[ex].priority;
}

void cpu_set_exception_priority(cpu_t *cpu, arm_exception ex, int16_t priority)
{
    if (cpu->exceptions[ex].fixed_priority)
        abort();

    cpu->exceptions[ex].priority = priority;
}
