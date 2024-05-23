#include "arm.h"
#include "byte_util.h"
#include "config.h"
#include "cpu.h"
#include "pseudocode.h"

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

#define SIGNEXTEND8_32(value) ((uint32_t)(int8_t)((value) & 0xFF))
#define SIGNEXTEND16_32(value) ((uint32_t)(int16_t)((value) & 0xFFFF))

#define OPERAND(n) cpu_load_operand(cpu, &i->detail->arm.operands[(n)], NULL)
#define OPERAND_C(n) cpu_load_operand(cpu, &i->detail->arm.operands[(n)], &carry)
#define OPERAND_REG(n) (assert(i->detail->arm.operands[(n)].type == ARM_OP_REG), cpu_reg_read(cpu, i->detail->arm.operands[(n)].reg))

#define UPDATE_N(cpu, value) (cpu)->xpsr.apsr_n = ((value) >> 31) == 1
#define UPDATE_Z(cpu, value) (cpu)->xpsr.apsr_z = (value) == 0
#define UPDATE_C(cpu, carry) (cpu)->xpsr.apsr_c = (carry) ? 1 : 0
#define UPDATE_V(cpu, overflow) (cpu)->xpsr.apsr_v = (overflow) ? 1 : 0

#define UPDATE_NZ                 \
    if (update_flags)             \
    {                             \
        UPDATE_N((cpu), (value)); \
        UPDATE_Z((cpu), (value)); \
    }

#define UPDATE_NZC                \
    if (update_flags)             \
    {                             \
        UPDATE_N((cpu), (value)); \
        UPDATE_Z((cpu), (value)); \
        UPDATE_C((cpu), (carry)); \
    }

#define UPDATE_NZCV                  \
    if (update_flags)                \
    {                                \
        UPDATE_N((cpu), (value));    \
        UPDATE_Z((cpu), (value));    \
        UPDATE_C((cpu), (carry));    \
        UPDATE_V((cpu), (overflow)); \
    }

#define WRITEBACK(op_n)                                          \
    if (detail->writeback)                                       \
    {                                                            \
        assert(detail->operands[op_n].type == ARM_OP_REG);       \
        cpu_reg_write(cpu, detail->operands[op_n].reg, address); \
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

typedef union
{
    struct
    {
        unsigned int mask : 5;
        unsigned int firstcond : 3;
    };
    struct
    {
        unsigned int : 4;
        unsigned int cond : 4;
    };
    uint8_t value;
} itstate_t;

typedef union
{
    struct
    {
        uint32_t lower : 32;
        uint32_t upper : 32;
    };
    uint64_t value;
} vreg_t;

static_assert(sizeof(vreg_t) == 8);

struct cpu_inst_t
{
    jmp_buf *fault_jmp_buf;
    bool has_fault_jmp;

    runlog_t *runlog;

    uint32_t core_regs[ARM_REG_ENDING - 1];
    uint32_t sp_main, sp_process;
    vreg_t d[32];

    uint32_t control, faultmask, basepri, primask;
    xPSR_t xpsr;

    itstate_t itstate;

    arm_mode mode;

    csh cs;
    uint8_t *program;
    size_t program_size;

    cs_insn *inst;
    cs_insn **inst_by_pc;

    cs_insn *last_external_inst;

    size_t exception_count, pending_exception_count;
    exception_t exceptions[ARM_EXC_EXTERNAL_END + 1];
    arm_exception active_exceptions[MAX_EXECUTING_EXCEPTIONS]; // Stack
    size_t active_exception_count;

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
            cpu_reg_read(cpu, ARM_REG_SP),
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

static uint32_t cpu_load_operand(cpu_t *cpu, cs_arm_op *op, bool *carry_out)
{
    if (op->type == ARM_OP_IMM)
    {
        assert(op->shift.type == ARM_SFT_INVALID);
        return op->imm;
    }

    assert(op->type == ARM_OP_REG);

    uint32_t value = cpu_reg_read(cpu, op->reg);

    if (op->shift.type != ARM_SFT_INVALID)
    {
        bool carry = cpu->xpsr.apsr_c;
        value = Shift_C(value, op->shift.type, op->shift.value, &carry);

        if (carry_out)
            *carry_out = carry;
    }

    return value;
}

static void cpu_store_operand(cpu_t *cpu, cs_arm_op *op, uint32_t value, size_t size)
{
    switch (op->type)
    {
    case ARM_OP_REG:
        cpu_reg_write(cpu, op->reg, value);
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

static bool cpu_in_it_block(cpu_t *cpu)
{
    return (cpu->itstate.value & 0xF) != 0;
}

static void cpu_it_advance(cpu_t *cpu)
{
    if ((cpu->itstate.value & 0x7) == 0)
        cpu->itstate.value = 0;
    else
        cpu->itstate.mask <<= 1;
}

static arm_cc cpu_current_cond(cpu_t *cpu, cs_insn *i)
{
    if (i->id == ARM_INS_B)
        return i->detail->arm.cc;

    if (cpu->itstate.value == 0)
        return ARM_CC_AL;

    assert(cpu_in_it_block(cpu));

    uint8_t cond = cpu->itstate.cond;
    cpu_it_advance(cpu);

    switch (cond)
    {
    case 0: // 0000
        return ARM_CC_EQ;
    case 1: // 0001
        return ARM_CC_NE;
    case 2: // 0010
        return ARM_CC_HS;
    case 3: // 0011
        return ARM_CC_LO;
    case 4: // 0100
        return ARM_CC_MI;
    case 5: // 0101
        return ARM_CC_PL;
    case 6: // 0110
        return ARM_CC_VS;
    case 7: // 0111
        return ARM_CC_VC;
    case 8: // 1000
        return ARM_CC_HI;
    case 9: // 1001
        return ARM_CC_LS;
    case 10: // 1010
        return ARM_CC_GE;
    case 11: // 1011
        return ARM_CC_LT;
    case 12: // 1100
        return ARM_CC_GT;
    case 13: // 1101
        return ARM_CC_LE;
    case 14: // 1110
    case 15: // 1111
        return ARM_CC_AL;

    default:
        return ARM_CC_INVALID;
    }
}

static bool cpu_condition_passed(cpu_t *cpu, cs_insn *i)
{
    arm_cc cc = cpu_current_cond(cpu, i);

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

    // If we just branched before taking the exception, the instruction at $PC hasn't been executed yet.
    // Thus, the next instruction to execute after returning from the exception would be the one at $PC.
    uint32_t next_addr = cpu->branched ? this_addr : (this_addr + cpu_insn_at(cpu, this_addr)->size);

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

arm_exception cpu_get_active_exception(cpu_t *cpu)
{
    if (cpu->active_exception_count == 0)
        return ARM_EXC_NONE;

    return cpu->active_exceptions[cpu->active_exception_count - 1];
}

void cpu_exception_set_pending(cpu_t *cpu, arm_exception ex)
{
    if (!cpu->exceptions[ex].pending)
    {
        cpu->pending_exception_count++;
        cpu->exceptions[ex].pending = true;

        LOG_CPU_EX("Exception %d is now pending", ex);
    }
}

static arm_exception cpu_exception_get_pending(cpu_t *cpu)
{
    if (cpu->pending_exception_count == 0)
        return 0;

    int16_t min_priority = ARM_MAX_PRIORITY;
    arm_exception min_ex = 0;
    int16_t current_priority = cpu_execution_priority(cpu);

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

void cpu_exception_clear_pending(cpu_t *cpu, arm_exception ex)
{
    if (cpu->exceptions[ex].pending)
    {
        cpu->pending_exception_count--;
        cpu->exceptions[ex].pending = false;

        LOG_CPU_EX("Exception %d is no longer pending", ex);
    }
}

bool cpu_exception_is_pending(cpu_t *cpu, arm_exception ex)
{
    return cpu->exceptions[ex].pending;
}

bool cpu_exception_is_active(cpu_t *cpu, arm_exception ex)
{
    return cpu->exceptions[ex].active;
}

void cpu_exception_set_enabled(cpu_t *cpu, arm_exception ex, bool enabled)
{
    if (cpu->exceptions[ex].fixed_enabled)
        abort();

    cpu->exceptions[ex].enabled = enabled;
}

bool cpu_exception_get_enabled(cpu_t *cpu, arm_exception ex)
{
    return cpu->exceptions[ex].enabled;
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

    uint32_t xpsr = cpu_sysreg_read(cpu, ARM_SYSREG_XPSR);

    memreg_write(cpu->mem, frameptr, cpu->core_regs[ARM_REG_R0], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x4, cpu->core_regs[ARM_REG_R1], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x8, cpu->core_regs[ARM_REG_R2], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0xC, cpu->core_regs[ARM_REG_R3], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x10, cpu->core_regs[ARM_REG_R12], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x14, cpu->core_regs[ARM_REG_LR], SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x18, cpu_exception_return_address(cpu, ex, sync), SIZE_WORD);
    memreg_write(cpu->mem, frameptr + 0x1C, (xpsr & ~(1 << 9)) | (frameptralign << 9), SIZE_WORD);

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
    cpu_sysreg_write(cpu, ARM_SYSREG_XPSR, new_psr, true);
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
    cpu->itstate.value = 0;

    cpu->control &= ~(1 << CONTROL_FPCA);
    cpu->control &= ~(1 << CONTROL_SPSEL);

    cpu->exceptions[ex].active = true;
    cpu->active_exceptions[cpu->active_exception_count++] = ex;

    // TODO: SCS_UpdateStatusRegs
}

static void cpu_exception_entry(cpu_t *cpu, arm_exception ex, bool sync)
{
    LOG_CPU_EX("Entering exception %d from 0x%08X", ex, cpu->core_regs[ARM_REG_PC]);

    if (cpu->runlog)
        runlog_exception_enter(cpu->runlog, ex);

    cpu_push_stack(cpu, ex, sync);
    cpu_exception_taken(cpu, ex);

    cpu_exception_clear_pending(cpu, ex);
}

static void cpu_exception_return(cpu_t *cpu, uint32_t exc_return)
{
    assert(cpu->mode == ARM_MODE_HANDLER);

    arm_exception returning_exception_number = cpu->xpsr.ipsr;
    uint32_t nested_activation = 0;

    if (cpu->runlog)
        runlog_exception_exit(cpu->runlog, returning_exception_number);

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
    cpu->active_exception_count--;

    if (cpu->xpsr.ipsr != 2)
        cpu->faultmask = 0;

    cpu_pop_stack(cpu, frameptr, exc_return);

    arm_exception pending = cpu_exception_get_pending(cpu);
    if (pending != 0)
    {
        cpu_exception_entry(cpu, pending, false);
    }
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
                value = SIGNEXTEND8_32(value);
                break;

            case SIZE_HALFWORD:
                value = SIGNEXTEND16_32(value);
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

static inline void cpu_decode_arithmetic(cpu_t *cpu, cs_insn *i, uint32_t *op0_val, uint32_t *op1_val, bool *carry)
{
    cs_arm *detail = &i->detail->arm;

    assert(detail->op_count == 2 || detail->op_count == 3);
    assert(detail->operands[0].type == ARM_OP_REG);

    cs_arm_op *op1 = &detail->operands[detail->op_count == 2 ? 0 : 1];
    cs_arm_op *op2 = &detail->operands[detail->op_count == 2 ? 1 : 2];

    assert(op1->type == ARM_OP_REG);
    *op0_val = cpu_reg_read(cpu, op1->reg);

    *carry = cpu->xpsr.apsr_c;

    if (op2->type == ARM_OP_IMM)
    {
        // (immediate)
        *op1_val = op2->imm;
        *carry = CalculateThumbExpandCarry(i->bytes, op2->imm, *carry);
    }
    else
    {
        // (register)
        assert(op2->type == ARM_OP_REG);
        *op1_val = cpu_load_operand(cpu, op2, carry);
    }
}

cpu_t *cpu_new(uint8_t *program, size_t program_size, memreg_t *mem, size_t max_external_interrupts, size_t priority_bits)
{
    cpu_t *cpu = calloc(1, sizeof(cpu_t));

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

    cpu->inst_by_pc = calloc(program_size / 2, sizeof(cs_insn *));

    return cpu;
}

void cpu_free(cpu_t *cpu)
{
    for (size_t i = 0; i < cpu->program_size / 2; i++)
    {
        cs_insn *ins = cpu->inst_by_pc[i];

        if (ins)
            cs_free(cpu->inst_by_pc[i], 1);
    }

    if (cpu->last_external_inst)
        cs_free(cpu->last_external_inst, 1);

    free(cpu->inst_by_pc);
    free(cpu);
}

void cpu_reset(cpu_t *cpu)
{
    memset(cpu->core_regs, 0, sizeof(cpu->core_regs));
    memset(cpu->d, 0, sizeof(cpu->d));

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
    cpu->itstate.value = 0;

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

    if (pc < cpu->program_size)
    {
        // Optimized path for instrutions in NRF52 program flash

        cs_insn **insn = &cpu->inst_by_pc[pc / 2];

        if (!*insn)
        {
            size_t n = cs_disasm(cpu->cs, &cpu->program[pc], cpu->program_size - pc, pc, 1, insn);

            if (n == 0)
            {
                fprintf(stderr, "Failed to disassemble code at 0x%08X\n", pc);
                abort();
            }
        }

        return *insn;
    }

    uint32_t code = memreg_read(cpu->mem, pc);

    if (cpu->last_external_inst)
        cs_free(cpu->last_external_inst, 1);

    // TODO: Reuse the same buffer for all external instructions using cs_disasm_iter
    size_t n = cs_disasm(cpu->cs, (const uint8_t *)&code, sizeof(code), pc, 1, &cpu->last_external_inst);

    if (n == 0)
    {
        fprintf(stderr, "Failed to disassemble code at 0x%08X\n", pc);
        abort();
    }

    assert(n == 1);

    return cpu->last_external_inst;
}

void cpu_execute_instruction(cpu_t *cpu, cs_insn *i, uint32_t next_pc)
{
    uint32_t op0, op1, value, address;
    cs_arm *detail = &i->detail->arm;

    LOG_CPU_INST("%s %s", i->mnemonic, i->op_str);

    switch (i->id)
    {
    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
    case ARM_INS_IT:
        break;
    default:
        if (!cpu_condition_passed(cpu, i))
            return;
        break;
    }

    bool update_flags = detail->update_flags;
    if (cpu_in_it_block(cpu) && i->size == 2 && i->id != ARM_INS_CMP && i->id != ARM_INS_CMN && i->id != ARM_INS_TST)
        update_flags = false;

    bool carry = false, overflow = false;

    switch (i->id)
    {
    case ARM_INS_ADC:
        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        if (i->size == 4)
        {
            // Fix Capstone bug where update_flags is always true on ADC T2
            update_flags = i->bytes[0] & (1 << 4);
        }

        carry = cpu->xpsr.apsr_c;
        value = AddWithCarry(op0, op1, &carry, &overflow);

        cpu_store_operand(cpu, &detail->operands[0], value, SIZE_WORD);

        UPDATE_NZCV;
        break;

    case ARM_INS_ADD:
        assert(detail->operands[0].type == ARM_OP_REG);
        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = false;
        value = AddWithCarry(op0, op1, &carry, &overflow);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZCV;
        break;

    case ARM_INS_ADR:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_IMM);

        value = cpu_reg_read(cpu, ARM_REG_PC);

        if (detail->operands[1].subtracted)
            value -= detail->operands[1].imm;
        else
            value += detail->operands[1].imm;

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_AND:
        assert(detail->op_count == 2 || detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        carry = cpu->xpsr.apsr_c;

        if (detail->op_count == 2)
        {
            op1 = OPERAND_REG(0);
        }
        else
        {
            if (detail->operands[2].type == ARM_OP_IMM)
            {
                op1 = detail->operands[2].imm;

                if (i->size == 4)
                    carry = CalculateThumbExpandCarry(i->bytes, detail->operands[2].imm, carry);
            }
            else
            {
                op1 = OPERAND_C(2);
            }
        }

        value = op0 & op1;
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_ASR:
        op0 = OPERAND_REG(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = cpu->xpsr.apsr_c;
        value = Shift_C(op0, ARM_SFT_ASR, op1 & 0xFF, &carry);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_B:
    case ARM_INS_BX:
        assert(detail->op_count == 1);

        BRANCH_WRITE_PC(cpu, OPERAND(0) | 1);
        break;

    case ARM_INS_BFC:
    {
        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_IMM);
        assert(detail->operands[2].type == ARM_OP_IMM);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg);

        uint32_t mask = ((1 << detail->operands[2].imm) - 1) << detail->operands[1].imm;
        value = op0 & ~mask;

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;
    }

    case ARM_INS_BFI:
    {
        assert(detail->op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_IMM);
        assert(detail->operands[3].type == ARM_OP_IMM);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg);
        op1 = cpu_reg_read(cpu, detail->operands[1].reg);

        uint32_t shift = detail->operands[2].imm;
        uint32_t mask = (1 << detail->operands[3].imm) - 1;

        op0 &= ~(mask << shift);
        op0 |= (op1 & mask) << shift;

        cpu_reg_write(cpu, detail->operands[0].reg, op0);
        break;
    }

    case ARM_INS_BIC:
        cpu_decode_arithmetic(cpu, i, &op0, &op1, &carry);

        value = op0 & ~op1;
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_BL:
    case ARM_INS_BLX:
        assert(detail->op_count == 1);

        cpu_reg_write(cpu, ARM_REG_LR, next_pc | 1);
        BRANCH_WRITE_PC(cpu, OPERAND(0) | 1);
        break;

    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
        assert(detail->op_count == 2);
        op0 = OPERAND(0);
        op1 = OPERAND(1);

        if ((op0 == 0) == (i->id == ARM_INS_CBZ))
            BRANCH_WRITE_PC(cpu, op1 | 1);
        break;

    case ARM_INS_CLZ:
        assert(detail->op_count == 2);

        op0 = OPERAND_REG(0);
        op1 = OPERAND_REG(1);

        value = op1 == 0 ? 32 : __builtin_clz(op1);
        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_CMN:
        assert(detail->update_flags);
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg);
        op1 = OPERAND(1);

        value = AddWithCarry(op0, op1, &carry, &overflow);

        UPDATE_NZCV
        break;

    case ARM_INS_CMP:
        assert(detail->update_flags);
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg);
        op1 = OPERAND(1);

        carry = true;
        value = AddWithCarry(op0, ~op1, &carry, &overflow);

        UPDATE_NZCV
        break;

    case ARM_INS_CPS:
        if (cpu_is_privileged(cpu))
        {
            if (detail->cps_mode == ARM_CPSMODE_IE)
            {
                if ((detail->cps_flag & ARM_CPSFLAG_I) != 0)
                    CLEAR(cpu->primask, 0);
                if ((detail->cps_flag & ARM_CPSFLAG_F) != 0)
                    CLEAR(cpu->faultmask, 0);
            }
            else if (detail->cps_mode == ARM_CPSMODE_ID)
            {
                if ((detail->cps_flag & ARM_CPSFLAG_I) != 0)
                    SET(cpu->primask, 0);

                if ((detail->cps_flag & ARM_CPSFLAG_F) != 0 && cpu_execution_priority(cpu) > -1)
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
    case ARM_INS_PLD:
    case ARM_INS_PLI:
        // Do nothing
        break;

    case ARM_INS_EOR:
        cpu_decode_arithmetic(cpu, i, &op0, &op1, &carry);

        value = op0 ^ op1;
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_IT:
    {
        assert(i->size == 2);
        assert(i->bytes[1] == 0xBF);

        cpu->itstate.value = i->bytes[0];
        break;
    }

    case ARM_INS_LDM:
        assert(detail->op_count >= 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        address = cpu_reg_read(cpu, detail->operands[0].reg);

        for (int n = 0; n < detail->op_count - 1; n++)
        {
            value = memreg_read(cpu->mem, address);
            address += 4;

            cpu_reg_write(cpu, detail->operands[n + 1].reg, value);
        }

        // TODO: Check if registers<n> == '0', else don't write back
        if (detail->writeback)
            cpu_reg_write(cpu, detail->operands[0].reg, address);
        break;

    case ARM_INS_LDMDB:
        assert(detail->op_count >= 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg) - 4 * (detail->op_count - 1);
        address = op0;

        for (int n = 0; n < detail->op_count - 1; n++)
        {
            value = memreg_read(cpu->mem, address);
            address += 4;

            cpu_reg_write(cpu, detail->operands[n + 1].reg, value);
        }

        // TODO: Check if registers<n> == '0', else don't write back
        if (detail->writeback)
            cpu_reg_write(cpu, detail->operands[0].reg, op0);
        break;

    case ARM_INS_LDR:
    case ARM_INS_LDREX:
        cpu_do_load(cpu, detail, SIZE_WORD, x(FFFF, FFFF) << 2, false);
        break;

    case ARM_INS_LDRB:
        cpu_do_load(cpu, detail, SIZE_BYTE, x(FFFF, FFFF), false);
        break;

    case ARM_INS_LDRSB:
        cpu_do_load(cpu, detail, SIZE_BYTE, x(FFFF, FFFF), true);
        break;

    case ARM_INS_LDRD:
        value = cpu_mem_operand_address(cpu, &detail->operands[2]);

        cpu_store_operand(cpu, &detail->operands[0], memreg_read(cpu->mem, value), SIZE_WORD);
        cpu_store_operand(cpu, &detail->operands[1], memreg_read(cpu->mem, value + 4), SIZE_WORD);
        break;

    case ARM_INS_LDRH:
        cpu_do_load(cpu, detail, SIZE_HALFWORD, x(FFFF, FFFF) << 1, false);
        break;

    case ARM_INS_LDRSH:
        cpu_do_load(cpu, detail, SIZE_HALFWORD, x(FFFF, FFFF) << 1, true);
        break;

    case ARM_INS_LSL:
        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = cpu->xpsr.apsr_c;
        value = Shift_C(op0, ARM_SFT_LSL, op1, &carry);

        cpu_store_operand(cpu, &detail->operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_LSR:
        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = cpu->xpsr.apsr_c;
        value = Shift_C(op0, ARM_SFT_LSR, op1 & 0xFF, &carry);

        cpu_store_operand(cpu, &detail->operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_MLA:
    case ARM_INS_MLS:
        assert(detail->op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_REG);
        assert(detail->operands[3].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);
        op1 = cpu_reg_read(cpu, detail->operands[2].reg);
        value = cpu_reg_read(cpu, detail->operands[3].reg);

        if (i->id == ARM_INS_MLA)
            value += op0 * op1;
        else
            value -= op0 * op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_MOV:
    case ARM_INS_MOVS:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        value = OPERAND(1);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZ; // FIXME: Carry should also be set sometimes but it seems like Capstone doesn't expose it
        break;

    case ARM_INS_MRS:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_SYSREG);

        value = cpu_sysreg_read(cpu, detail->operands[1].reg);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_MSR:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_SYSREG);
        assert(detail->operands[1].type == ARM_OP_REG);

        value = cpu_reg_read(cpu, detail->operands[1].reg);

        cpu_sysreg_write(cpu, detail->operands[0].reg, value, false);
        break;

    case ARM_INS_MUL:
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND_REG(2);

        value = op0 * op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZ
        break;

    case ARM_INS_MVN:
        assert(detail->operands[0].type == ARM_OP_REG);

        carry = cpu->xpsr.apsr_c;

        if (detail->op_count == 2 && detail->operands[1].type == ARM_OP_IMM)
            carry = CalculateThumbExpandCarry(i->bytes, detail->operands[1].imm, carry);

        op1 = OPERAND_C(1);

        value = ~op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_ORN:
        cpu_decode_arithmetic(cpu, i, &op0, &op1, &carry);

        value = op0 | ~op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_ORR:
        cpu_decode_arithmetic(cpu, i, &op0, &op1, &carry);

        value = op0 | op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_PKHBT:
    case ARM_INS_PKHTB:
        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);
        op1 = OPERAND(2);

        if (i->id == ARM_INS_PKHTB)
            value = (op0 & x(FFFF, 0000)) | (op1 & 0xFFFF);
        else
            value = (op1 & x(FFFF, 0000)) | (op0 & 0xFFFF);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_POP:
        op0 = cpu_reg_read(cpu, ARM_REG_SP);

        cpu_reg_write(cpu, ARM_REG_SP, op0 + 4 * detail->op_count);

        for (int n = 0; n < detail->op_count; n++)
        {
            value = memreg_read(cpu->mem, op0);

            cpu_store_operand(cpu, &detail->operands[n], value, SIZE_WORD);

            op0 += 4;
        }
        break;

    case ARM_INS_PUSH:
        cpu_do_stmdb(cpu, ARM_REG_SP, true, &detail->operands[0], detail->op_count);
        break;

    case ARM_INS_RBIT:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        value = cpu_reg_read(cpu, detail->operands[1].reg);

        // From http://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel
        value = ((value >> 1) & 0x55555555) | ((value & 0x55555555) << 1);
        value = ((value >> 2) & 0x33333333) | ((value & 0x33333333) << 2);
        value = ((value >> 4) & 0x0F0F0F0F) | ((value & 0x0F0F0F0F) << 4);
        value = ((value >> 8) & 0x00FF00FF) | ((value & 0x00FF00FF) << 8);
        value = (value >> 16) | (value << 16);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_REV:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);

        value = ((op0 & 0xFF) << 24) | ((op0 & 0xFF00) << 8) | ((op0 & 0xFF0000) >> 8) | ((op0 & 0xFF000000) >> 24);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_REV16:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);

        value = ((op0 & 0xFF) << 8) | ((op0 & 0xFF00) >> 8) | ((op0 & 0xFF0000) << 8) | ((op0 & 0xFF000000) >> 8);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_REVSH:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);

        value = ((op0 & 0xFF) << 8) | ((op0 & 0xFF00) >> 8);

        if (value & 0x8000)
            value |= 0xFFFF0000;

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_ROR:
        op0 = OPERAND_REG(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = cpu->xpsr.apsr_c;
        value = Shift_C(op0, ARM_SFT_ROR, op1 & 0xFF, &carry);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_RRX:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);

        carry = cpu->xpsr.apsr_c;
        value = Shift_C(op0, ARM_SFT_RRX, 1, &carry);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_RSB:
        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);
        op1 = OPERAND(2);

        carry = true;
        value = AddWithCarry(~op0, op1, &carry, &overflow);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZCV
        break;

    case ARM_INS_SADD16:
    {
        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND_REG(2);

        int32_t sum1 = (int16_t)(op0 & 0xFFFF) + (int16_t)(op1 & 0xFFFF);
        int32_t sum2 = (int16_t)(op0 >> 16) + (int16_t)(op1 >> 16);

        value = (sum2 << 16) | (sum1 & 0xFFFF);
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        cpu->xpsr.apsr_ge0 = cpu->xpsr.apsr_ge1 = sum1 >= 0;
        cpu->xpsr.apsr_ge2 = cpu->xpsr.apsr_ge3 = sum2 >= 0;
        break;
    }

    case ARM_INS_SADD8:
    {
        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND_REG(2);

        int16_t sum1 = (int8_t)(op0 & 0xFF) + (int8_t)(op1 & 0xFF);
        int16_t sum2 = (int8_t)(op0 >> 8) + (int8_t)(op1 >> 8);
        int16_t sum3 = (int8_t)(op0 >> 16) + (int8_t)(op1 >> 16);
        int16_t sum4 = (int8_t)(op0 >> 24) + (int8_t)(op1 >> 24);

        value = (sum4 << 24) | ((sum3 & 0xFF) << 16) | ((sum2 & 0xFF) << 8) | (sum1 & 0xFF);
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        cpu->xpsr.apsr_ge0 = sum1 >= 0;
        cpu->xpsr.apsr_ge1 = sum2 >= 0;
        cpu->xpsr.apsr_ge2 = sum3 >= 0;
        cpu->xpsr.apsr_ge3 = sum4 >= 0;
        break;
    }

    case ARM_INS_SASX:
    {
        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND_REG(2);

        int32_t diff = (int16_t)(op0 & 0xFFFF) - (int16_t)(op1 >> 16);
        int32_t sum = (int16_t)(op0 >> 16) + (int16_t)(op1 & 0xFFFF);

        value = ((sum & 0xFFFF) << 16) | (diff & 0xFFFF);
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        cpu->xpsr.apsr_ge0 = cpu->xpsr.apsr_ge1 = diff >= 0;
        cpu->xpsr.apsr_ge2 = cpu->xpsr.apsr_ge3 = sum >= 0;
        break;
    }

    case ARM_INS_SBC:
        cpu_decode_arithmetic(cpu, i, &op0, &op1, &carry);

        if (i->size == 4)
        {
            // FIXME: Capstone bug, update_flags is always true on SBC (immediate) and SBC (register) T2
            update_flags = i->bytes[0] & (1 << 4);
        }

        carry = cpu->xpsr.apsr_c;
        value = AddWithCarry(op0, ~op1, &carry, &overflow);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZCV;
        break;

    case ARM_INS_SBFX:
    {
        op1 = OPERAND(1);
        uint32_t lsb = OPERAND(2);
        uint32_t width = OPERAND(3);

        uint32_t mask = 1 << (width - 1);

        assert(lsb + width <= 32);

        value = (op1 >> lsb) & ((1 << width) - 1);
        value = (value ^ mask) - mask; // Sign extend https://stackoverflow.com/a/17719010

        cpu_store_operand(cpu, &detail->operands[0], value, SIZE_WORD);
        break;
    }

    case ARM_INS_SDIV:
    case ARM_INS_UDIV:
        assert(detail->op_count == 2 || detail->op_count == 3);

        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->op_count < 3 || detail->operands[2].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[detail->op_count == 3 ? 1 : 0].reg);
        op1 = cpu_reg_read(cpu, detail->operands[detail->op_count == 3 ? 2 : 1].reg);

        // TODO: Exception if op1 is zero
        assert(op1 != 0);

        if (i->id == ARM_INS_SDIV)
            value = (int32_t)op0 / (int32_t)op1;
        else
            value = op0 / op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_SEL:
        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND_REG(2);

        value = (cpu->xpsr.apsr_ge0 ? op0 & 0xFF : op1 & 0xFF) |
                (cpu->xpsr.apsr_ge1 ? op0 & 0xFF00 : op1 & 0xFF00) |
                (cpu->xpsr.apsr_ge2 ? op0 & 0xFF0000 : op1 & 0xFF0000) |
                (cpu->xpsr.apsr_ge3 ? op0 & 0xFF000000 : op1 & 0xFF000000);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_SMULL:
    {
        assert(detail->op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        uint64_t result = (int64_t)(int32_t)OPERAND_REG(2) * (int64_t)(int32_t)OPERAND_REG(3);

        cpu_reg_write(cpu, detail->operands[0].reg, result & x(FFFF, FFFF));
        cpu_reg_write(cpu, detail->operands[1].reg, result >> 32);
        break;
    }

    case ARM_INS_STM:
        assert(detail->op_count >= 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg);

        for (size_t n = 0; n < detail->op_count; n++)
        {
            assert(detail->operands[n].type == ARM_OP_REG);

            memreg_write(cpu->mem, op0, cpu_reg_read(cpu, detail->operands[n].reg), SIZE_WORD);

            op0 += 4;
        }

        if (detail->writeback)
            cpu_reg_write(cpu, detail->operands[0].reg, op0);
        break;

    case ARM_INS_STR:
        cpu_do_store(cpu, detail, SIZE_WORD, false);
        break;

    case ARM_INS_STRB:
        cpu_do_store(cpu, detail, SIZE_BYTE, false);
        break;

    case ARM_INS_STRD:
        cpu_do_store(cpu, detail, SIZE_WORD, true);
        break;

    case ARM_INS_STREX:
        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_MEM);

        op0 = cpu_mem_operand_address(cpu, &detail->operands[2]);

        cpu_reg_write(cpu, detail->operands[0].reg, 0);
        memreg_write(cpu->mem, op0, cpu_reg_read(cpu, detail->operands[1].reg), SIZE_WORD);
        break;

    case ARM_INS_STRH:
        cpu_do_store(cpu, detail, SIZE_HALFWORD, false);
        break;

    case ARM_INS_STMDB:
        cpu_do_stmdb(cpu, detail->operands[0].reg, detail->writeback, &detail->operands[1], detail->op_count - 1);
        break;

    case ARM_INS_SUB:
        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = true;
        value = AddWithCarry(op0, ~op1, &carry, &overflow);

        cpu_store_operand(cpu, &detail->operands[0], value, SIZE_WORD);

        UPDATE_NZCV
        break;

    case ARM_INS_SVC:
        cpu_exception_set_pending(cpu, ARM_EXC_SVC);
        break;

    case ARM_INS_SXTAB:
        assert(detail->op_count == 3); // TODO: Handle rotation case
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);
        op1 = cpu_reg_read(cpu, detail->operands[2].reg);

        value = op0 + SIGNEXTEND8_32(op1);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_SXTAH:
        assert(detail->op_count == 3); // TODO: Handle rotation case
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);
        op1 = cpu_reg_read(cpu, detail->operands[2].reg);

        value = op0 + SIGNEXTEND16_32(op1);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_SXTB:
        assert(detail->op_count == 2); // TODO: Handle rotation case
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op1 = cpu_reg_read(cpu, detail->operands[1].reg);
        value = SIGNEXTEND8_32(op1);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_SXTH:
        assert(detail->op_count == 2); // TODO: Handle rotation case
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op1 = cpu_reg_read(cpu, detail->operands[1].reg);
        value = SIGNEXTEND16_32(op1);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_TBB:
    case ARM_INS_TBH:
        assert(detail->op_count == 1);
        assert(detail->operands[0].type == ARM_OP_MEM);

        op0 = cpu_mem_operand_address(cpu, &detail->operands[0]);
        value = memreg_read(cpu->mem, op0) & (i->id == ARM_INS_TBB ? 0xFF : 0xFFFF);

        cpu_reg_write(cpu, ARM_REG_PC, (cpu_reg_read(cpu, ARM_REG_PC) + value * 2) | 1);
        break;

    case ARM_INS_TEQ:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg);
        op1 = OPERAND(1);

        value = op0 ^ op1;

        UPDATE_NZC
        break;

    case ARM_INS_TST:
        assert(detail->op_count == 2);
        assert(detail->operands[1].shift.value == 0);

        op0 = OPERAND(0);
        op1 = OPERAND(1);

        value = op0 & op1;

        UPDATE_NZ
        break;

    case ARM_INS_UADD8:
    {
        assert(detail->op_count == 3); // TODO: Implement 2-register case
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);
        op1 = cpu_reg_read(cpu, detail->operands[2].reg);

        uint16_t sum1 = (op0 & 0xFF) + (op1 & 0xFF);
        uint16_t sum2 = ((op0 >> 8) & 0xFF) + ((op1 >> 8) & 0xFF);
        uint16_t sum3 = ((op0 >> 16) & 0xFF) + ((op1 >> 16) & 0xFF);
        uint16_t sum4 = ((op0 >> 24) & 0xFF) + ((op1 >> 24) & 0xFF);

        cpu_reg_write(cpu, detail->operands[0].reg,
                      ((sum4 & 0xFF) << 24) |
                          ((sum3 & 0xFF) << 16) |
                          ((sum2 & 0xFF) << 8) |
                          (sum1 & 0xFF));

        cpu->xpsr.apsr_ge0 = sum1 > 0x100;
        cpu->xpsr.apsr_ge1 = sum2 > 0x100;
        cpu->xpsr.apsr_ge2 = sum3 > 0x100;
        cpu->xpsr.apsr_ge3 = sum4 > 0x100;
        break;
    }

    case ARM_INS_UBFX:
    {
        op1 = OPERAND(1);
        uint32_t lsb = OPERAND(2);
        uint32_t width = OPERAND(3);

        assert(lsb + width <= 32);

        value = (op1 >> lsb) & ((1 << width) - 1);

        cpu_store_operand(cpu, &detail->operands[0], value, SIZE_WORD);
        break;
    }

    case ARM_INS_UMLAL:
    {
        assert(detail->op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_REG);
        assert(detail->operands[3].type == ARM_OP_REG);

        uint64_t result = (uint64_t)cpu_reg_read(cpu, detail->operands[2].reg) * (uint64_t)cpu_reg_read(cpu, detail->operands[3].reg);
        result += ((uint64_t)cpu_reg_read(cpu, detail->operands[1].reg) << 32) | (uint64_t)cpu_reg_read(cpu, detail->operands[0].reg);

        cpu_reg_write(cpu, detail->operands[0].reg, result & x(FFFF, FFFF));
        cpu_reg_write(cpu, detail->operands[1].reg, result >> 32);
        break;
    }

    case ARM_INS_UMULL:
    {
        assert(detail->op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_REG);
        assert(detail->operands[3].type == ARM_OP_REG);

        uint64_t result = (uint64_t)cpu_reg_read(cpu, detail->operands[2].reg) * (uint64_t)cpu_reg_read(cpu, detail->operands[3].reg);

        cpu_reg_write(cpu, detail->operands[0].reg, result & x(FFFF, FFFF));
        cpu_reg_write(cpu, detail->operands[1].reg, result >> 32);
        break;
    }

    case ARM_INS_USAT:
        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_IMM);
        assert(detail->operands[2].type == ARM_OP_REG);

        op0 = detail->operands[1].imm;
        op1 = OPERAND(2);

        bool saturated = UnsignedSatQ(op1, op0, &value);
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        if (saturated)
            cpu->xpsr.apsr_q = 1;
        break;

    case ARM_INS_UXTB:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op1 = cpu_reg_read(cpu, detail->operands[1].reg);

        cpu_reg_write(cpu, detail->operands[0].reg, op1 & 0xFF);
        break;

    case ARM_INS_UXTH:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op1 = cpu_reg_read(cpu, detail->operands[1].reg);

        cpu_reg_write(cpu, detail->operands[0].reg, op1 & 0xFFFF);
        break;

    case ARM_INS_VLDR:
    {
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_MEM);

        uint32_t base = cpu_reg_read(cpu, detail->operands[1].mem.base);
        if (detail->operands[1].mem.base == ARM_REG_PC)
            base = ALIGN4(base);

        uint32_t address = detail->operands[1].subtracted ? base - detail->operands[1].mem.disp : base + detail->operands[1].mem.disp;

        if (detail->operands[0].reg >= ARM_REG_S0 && detail->operands[0].reg <= ARM_REG_S31)
        {
            cpu_reg_write(cpu, detail->operands[0].reg, memreg_read(cpu->mem, address));
        }
        else
        {
            assert(detail->operands[0].reg >= ARM_REG_D0 && detail->operands[0].reg <= ARM_REG_D31);

            uint32_t word1 = memreg_read(cpu->mem, address);
            uint32_t word2 = memreg_read(cpu->mem, address + 4);

            cpu->d[detail->operands[0].reg - ARM_REG_D0].value = (uint64_t)word1 | ((uint64_t)word2 << 32);
        }
        break;
    }

    // case ARM_INS_VLDMIA:
    case ARM_INS_VMRS:
    case ARM_INS_VMSR:
        // case ARM_INS_VSTMDB:
        LOG_CPU_INST("Implement instruction %d\n", i->id);
        // TODO: Implement
        break;

    case ARM_INS_VSTR:
    {
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_MEM);

        uint32_t base = cpu_reg_read(cpu, detail->operands[1].mem.base);
        uint32_t address = detail->operands[1].subtracted ? base - detail->operands[1].mem.disp : base + detail->operands[1].mem.disp;

        if (detail->operands[0].reg >= ARM_REG_S0 && detail->operands[0].reg <= ARM_REG_S31)
        {
            memreg_write(cpu->mem, address, cpu_reg_read(cpu, detail->operands[0].reg), SIZE_WORD);
        }
        else
        {
            assert(detail->operands[0].reg >= ARM_REG_D0 && detail->operands[0].reg <= ARM_REG_D31);

            memreg_write(cpu->mem, address, cpu->d[detail->operands[0].reg - ARM_REG_D0].lower, SIZE_WORD);
            memreg_write(cpu->mem, address + 4, cpu->d[detail->operands[0].reg - ARM_REG_D0].upper, SIZE_WORD);
        }
        break;
    }

    default:
        fprintf(stderr, "Unhandled instruction %s %s at 0x%08X\n", i->mnemonic, i->op_str, cpu->core_regs[ARM_REG_PC]);
        cpu_do_fault_jmp(cpu);
        abort();
    }
}

void cpu_step(cpu_t *cpu)
{
    dwt_increment_cycle(cpu->dwt);

    arm_exception pending;

    uint32_t pc = cpu->core_regs[ARM_REG_PC];

    cs_insn *i = cpu_insn_at(cpu, pc);
    if (i == NULL)
    {
        fprintf(stderr, "Failed to find instruction at 0x%08X\n", cpu->core_regs[ARM_REG_PC]);
        abort();
    }

    if (cpu->runlog)
        runlog_record_fetch(cpu->runlog, pc);

    uint32_t next = pc + i->size;

    cpu->branched = false;

    cpu_execute_instruction(cpu, i, next);

    if (cpu->runlog)
        runlog_record_execute(cpu->runlog, cpu_get_runlog_regs(cpu));

    pending = cpu_exception_get_pending(cpu);
    if (pending != 0)
        cpu_exception_entry(cpu, pending, false);

    if (!cpu->branched)
    {
        cpu->core_regs[ARM_REG_PC] = next;
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
        if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31)
        {
            int n = reg - ARM_REG_S0;
            if (n % 2 == 0)
                return cpu->d[n / 2].lower;
            else
                return cpu->d[n / 2].upper;
        }

        if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31)
            abort();

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
        // assert(value >= x(2000, 0000)); // Stack overflow

        *cpu_get_sp(cpu) = value & x(FFFF, FFFC); // Lowest 2 bits are always zero
        break;

    default:
        if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31)
        {
            int n = reg - ARM_REG_S0;
            if (n % 2 == 0)
                cpu->d[n / 2].lower = value;
            else
                cpu->d[n / 2].upper = value;
        }
        else if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31)
            abort();
        else
            cpu->core_regs[reg] = value;

        break;
    }
}

uint32_t cpu_sysreg_read(cpu_t *cpu, arm_sysreg reg)
{
    switch (reg)
    {
    case ARM_SYSREG_IPSR:
        return cpu->xpsr.ipsr;

    case ARM_SYSREG_XPSR:
    {
        uint32_t value = cpu->xpsr.value;
        value &= ~0x600F800; // Remove EPSR.IT bits
        value |= (cpu->itstate.value >> 6) << 25;
        value |= (cpu->itstate.value & 0x3F) << 10;
        value |= cpu_get_active_exception(cpu) & 0x1FF;
        return value;
    }

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

void cpu_sysreg_write(cpu_t *cpu, arm_sysreg reg, uint32_t value, bool can_update_it)
{
    switch (reg)
    {
    case ARM_SYSREG_XPSR:
    case ARM_SYSREG_APSR:
    case ARM_SYSREG_EPSR:
    case ARM_SYSREG_IPSR:
        cpu->xpsr.value = value;

        if (can_update_it)
            cpu->itstate.value = ((value >> 10) & 0x3F) | ((value >> 25) & 0x3) << 6;

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
