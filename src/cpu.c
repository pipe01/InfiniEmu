#include "arm.h"
#include "byte_util.h"
#include "config.h"
#include "cpu.h"
#include "fault.h"
#include "pseudocode.h"

#include "peripherals/peripheral.h"
#include "peripherals/dwt.h"
#include "peripherals/nvic.h"
#include "peripherals/dcb.h"
#include "peripherals/scb.h"
#include "peripherals/scb_fp.h"

#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define LOG(tag, msg, ...) printf("0x%08X: [" tag "] " msg "\n", cpu->core_regs[ARM_REG_PC], ##__VA_ARGS__)

#if ENABLE_LOG_CPU_EXCEPTIONS
#define LOG_CPU_EX(msg, ...) LOG("CPU_EX", msg, __VA_ARGS__)
#else
#define LOG_CPU_EX(...)
#endif

#if ENABLE_LOG_CPU_INSTRUCTIONS
#define LOG_CPU_INST(msg, ...) LOG("CPU_INST", msg, __VA_ARGS__)
#else
#define LOG_CPU_INST(...)
#endif

#define UNPREDICTABLE abort()

// TODO: Implement
#define BRANCH_WRITE_PC(cpu, pc) cpu_reg_write(cpu, ARM_REG_PC, pc)

#define SIGNEXTEND8_32(value) ((uint32_t)(int8_t)((value) & 0xFF))
#define SIGNEXTEND16_32(value) ((uint32_t)(int16_t)((value) & 0xFFFF))

#define OPERAND(n) load_operand(cpu, &i->detail->arm.operands[(n)], NULL)
#define OPERAND_C(n) load_operand(cpu, &i->detail->arm.operands[(n)], &carry)
#define OPERAND_REG(n) (assert(i->detail->arm.operands[(n)].type == ARM_OP_REG), cpu_reg_read(cpu, i->detail->arm.operands[(n)].reg))
#define OPERAND_IMM(n) (assert(i->detail->arm.operands[(n)].type == ARM_OP_IMM), i->detail->arm.operands[(n)].imm)

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

#define IS_DOUBLE(op) ((op).reg >= ARM_REG_D0 && (op).reg <= ARM_REG_D31)

#define MAX_EXECUTING_EXCEPTIONS 64

// static_assert(__STDC_IEC_559__, "Floating point operations are not IEEE 754 compliant");

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
    struct
    {
        float f_lower;
        float f_upper;
    };
    uint64_t value;
    double f_value;
} vreg_t;
static_assert(sizeof(vreg_t) == 8, "vreg_t size is not 8 bytes");

typedef union
{
    float f;
    uint32_t i;
} float32_t;
static_assert(sizeof(float32_t) == 4, "float32_t size is not 4 bytes");

#define FLOAT32_F(val) ((float32_t){.f = (val)})
#define FLOAT32_I(val) ((float32_t){.i = (val)})

typedef union
{
    double f;
    uint64_t i;
} float64_t;
static_assert(sizeof(float64_t) == 8, "float64_t size is not 8 bytes");

#define FLOAT64_F(val) ((float64_t){.f = (val)})
#define FLOAT64_I(val) ((float64_t){.i = (val)})

#define ROUNDF_TO_ZERO(val) ((val) > 0 ? floorf(val) : ceilf(val))
#define ROUNDD_TO_ZERO(val) ((val) > 0 ? floor(val) : ceil(val))

#if ENABLE_RUNLOG
#define DO_RUNLOG(...) \
    if (cpu->runlog)   \
    __VA_ARGS__
#else
#define DO_RUNLOG(...)
#endif

#if ASSERT_EXCEPTION_REGISTERS
arm_reg check_exc_registers[] = {
    ARM_REG_R0,
    ARM_REG_R1,
    ARM_REG_R2,
    ARM_REG_R3,
    ARM_REG_R4,
    ARM_REG_R5,
    ARM_REG_R6,
    ARM_REG_R7,
    ARM_REG_R8,
    ARM_REG_R9,
    ARM_REG_R10,
    ARM_REG_R11,
    ARM_REG_R12,
    ARM_REG_SP,
    ARM_REG_LR,
    ARM_REG_PC,
};
#endif

struct cpu_inst_t
{
    struct state
    {
        bool is_locked_up;

        uint32_t core_regs[ARM_REG_ENDING - 1];
        uint32_t sp_main, sp_process;
        vreg_t d[32];

        uint32_t faultmask, basepri, primask;
        CONTROL_t control;
        xPSR_t xpsr;

        itstate_t itstate;
        bool must_advance_it;

        arm_mode mode;

        size_t exception_count, pending_exception_count;
        exception_t exceptions[ARM_EXC_EXTERNAL_END + 1];
        arm_exception running_exceptions[MAX_EXECUTING_EXCEPTIONS]; // Stack
        uint32_t pending_exceptions[ARM_EXCEPTION_COUNT / 32];      // Bitfield
        size_t running_exception_count;
        int execution_priority;

        size_t sleep_fuel;

        bool branched;
    };

    jmp_buf *fault_jmp_buf;
    bool has_fault_jmp;

    state_store_t *state_store;

#if ENABLE_RUNLOG
    runlog_t *runlog;
#endif

    branch_cb_t branch_cb;
    void *branch_cb_userdata;

    struct
    {
        uint32_t address;
        bool read, write;
        mem_watchpoint_cb_t cb;
        void *userdata;
    } memory_watchpoint;

    csh cs;
    const uint8_t *program;
    size_t program_size;

    cs_insn *inst;
    cs_insn **inst_by_pc;

    cs_insn *last_external_inst;

#if ASSERT_EXCEPTION_REGISTERS
    uint32_t exception_regs[sizeof(check_exc_registers) / sizeof(arm_reg)][MAX_EXECUTING_EXCEPTIONS];
    size_t exception_regs_count;
#endif

    memory_map_t *mem;

    DWT_t *dwt;
    SCB_t *scb;
    SCB_FP_t *scb_fp;
    DCB_t *dcb;
    NVIC_t *nvic;
};

cs_insn *cpu_insn_at(cpu_t *cpu, uint32_t pc);

static void memory_map_write_traced(cpu_t *cpu, uint32_t addr, uint32_t value, byte_size_t size)
{
    DO_RUNLOG(runlog_record_memory_store(cpu->runlog, RUNLOG_REG_UNKNOWN, value, addr, size));

    if (cpu->memory_watchpoint.write && cpu->memory_watchpoint.address == addr)
    {
        uint32_t old_value = memory_map_read(cpu->mem, addr);

        memory_map_write(cpu->mem, addr, value, size);

        cpu->memory_watchpoint.cb(cpu, true, addr, size, old_value, value, cpu->memory_watchpoint.userdata);
    }
    else
    {
        memory_map_write(cpu->mem, addr, value, size);
    }
}

static uint32_t memory_map_read_traced(cpu_t *cpu, uint32_t addr, size_t size)
{
    uint32_t value = 0;

    memory_map_do_operation(cpu->mem, addr, size, &value);

    DO_RUNLOG(runlog_record_memory_load(cpu->runlog, addr, value, RUNLOG_REG_UNKNOWN, size));

    if (cpu->memory_watchpoint.read && cpu->memory_watchpoint.address == addr)
    {
        cpu->memory_watchpoint.cb(cpu, false, addr, size, value, value, cpu->memory_watchpoint.userdata);
    }

    return value;
}

static inline uint32_t memory_map_read_traced_word(cpu_t *cpu, uint32_t addr)
{
    return memory_map_read_traced(cpu, addr, SIZE_WORD);
}

static inline uint16_t memory_map_read_traced_halfword(cpu_t *cpu, uint32_t addr)
{
    return memory_map_read_traced(cpu, addr, SIZE_HALFWORD);
}

static inline uint8_t memory_map_read_traced_byte(cpu_t *cpu, uint32_t addr)
{
    return memory_map_read_traced(cpu, addr, SIZE_BYTE);
}

#if ENABLE_RUNLOG
static inline runlog_registers_t get_runlog_regs(cpu_t *cpu)
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
        fault_take(FAULT_UNKNOWN);
    }
}
#endif

static uint32_t mem_operand_address(cpu_t *cpu, cs_arm_op *op)
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

static uint32_t load_operand(cpu_t *cpu, cs_arm_op *op, bool *carry_out)
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

static void store_operand(cpu_t *cpu, cs_arm_op *op, uint32_t value, size_t size)
{
    switch (op->type)
    {
    case ARM_OP_REG:
        cpu_reg_write(cpu, op->reg, value);
        break;

    case ARM_OP_MEM:
    {
        uint32_t addr = ALIGN4(mem_operand_address(cpu, op));

        memory_map_write_traced(cpu, addr, value, size);
        break;
    }
    default:
        fprintf(stderr, "Unhandled operand type %d\n", op->type);
        fault_take(FAULT_CPU_INVALID_INSTRUCTION);
    }
}

static bool in_it_block(cpu_t *cpu)
{
    return (cpu->itstate.value & 0xF) != 0;
}

static void it_advance(cpu_t *cpu)
{
    cpu->must_advance_it = false;

    if ((cpu->itstate.value & 0x7) == 0)
    {
        cpu->itstate.value = 0;

#if ENABLE_LOG_CPU_IT
        LOG("IT", "Exiting IT block");
#endif
    }
    else
    {
        cpu->itstate.mask <<= 1;

#if ENABLE_LOG_CPU_IT
        LOG("IT", "Advancing IT block to 0x%X", cpu->itstate.value);
#endif
    }
}

static arm_cc current_cond(cpu_t *cpu, cs_insn *i)
{
    if (i->id == ARM_INS_B && !in_it_block(cpu))
        return i->detail->arm.cc;

    if (cpu->itstate.value == 0)
        return ARM_CC_AL;

    assert(in_it_block(cpu));

    cpu->must_advance_it = true;

    uint8_t cond = cpu->itstate.cond;

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

static bool condition_passed(cpu_t *cpu, cs_insn *i)
{
    arm_cc cc = current_cond(cpu, i);

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
        fault_take(FAULT_CPU_INVALID_CC);
    }
}

static bool is_privileged(cpu_t *cpu)
{
    return cpu->mode == ARM_MODE_HANDLER || !cpu->control.nPRIV;
}

static int calculate_execution_priority(cpu_t *cpu)
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

static void update_execution_priority(cpu_t *cpu)
{
    cpu->execution_priority = calculate_execution_priority(cpu);
}

static uint32_t exception_return_address(cpu_t *cpu, arm_exception ex, bool sync)
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

static void enter_lockup(cpu_t *cpu)
{
    if (!cpu->is_locked_up)
    {
        cpu->is_locked_up = true;

        LOG("LOCKUP", "Entering lockup state");
    }
}

arm_exception cpu_get_top_running_exception(cpu_t *cpu)
{
    if (cpu->running_exception_count == 0)
        return ARM_EXC_NONE;

    return cpu->running_exceptions[cpu->running_exception_count - 1];
}

void cpu_exception_set_pending(cpu_t *cpu, arm_exception ex)
{
    assert(ex < ARM_EXC_EXTERNAL_END);

    if (!cpu->exceptions[ex].pending)
    {
        cpu->pending_exception_count++;
        cpu->exceptions[ex].pending = true;
        cpu->pending_exceptions[ex / 32] |= 1 << (ex % 32);

        LOG_CPU_EX("Exception %d is now pending", ex);
    }
}

static arm_exception exception_get_pending(cpu_t *cpu)
{
    if (cpu->pending_exception_count == 0)
        return 0;

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

    if (min_priority >= cpu->execution_priority)
        return 0;

    return min_ex;
}

void cpu_exception_clear_pending(cpu_t *cpu, arm_exception ex)
{
    assert(ex < ARM_EXC_EXTERNAL_END);

    if (cpu->exceptions[ex].pending)
    {
        cpu->pending_exception_count--;
        cpu->exceptions[ex].pending = false;
        cpu->pending_exceptions[ex / 32] &= ~(1 << (ex % 32));

        LOG_CPU_EX("Exception %d is no longer pending", ex);
    }
}

bool cpu_exception_is_pending(cpu_t *cpu, arm_exception ex)
{
    assert(ex < ARM_EXC_EXTERNAL_END);

    if (cpu->pending_exception_count == 0)
        return false;

    return cpu->pending_exceptions[ex / 32] & (1 << (ex % 32));
}

uint32_t cpu_exception_get_pending_block(cpu_t *cpu, int block_num)
{
    return cpu->pending_exceptions[block_num];
}

bool cpu_exception_is_active(cpu_t *cpu, arm_exception ex)
{
    assert(ex < ARM_EXC_EXTERNAL_END);

    return cpu->exceptions[ex].active;
}

static void exception_set_active(cpu_t *cpu, arm_exception ex, bool active)
{
    assert(ex < ARM_EXC_EXTERNAL_END);

    if (cpu->exceptions[ex].active == active)
        return;

    cpu->exceptions[ex].active = active;
    update_execution_priority(cpu);

    if (active)
        cpu->running_exceptions[cpu->running_exception_count++] = ex;
    else
        cpu->running_exception_count--;
}

void cpu_exception_set_enabled(cpu_t *cpu, arm_exception ex, bool enabled)
{
    assert(ex < ARM_EXC_EXTERNAL_END);

    if (cpu->exceptions[ex].fixed_enabled)
        fault_take(FAULT_CPU_FIXED_EXCEPTION);

    cpu->exceptions[ex].enabled = enabled;
}

bool cpu_exception_get_enabled(cpu_t *cpu, arm_exception ex)
{
    assert(ex < ARM_EXC_EXTERNAL_END);

    return cpu->exceptions[ex].enabled;
}

static inline void check_vfp_enabled(cpu_t *cpu)
{
    uint32_t cpacr = scb_get_cpacr(cpu->scb);

    if ((cpacr & 0x300000) == 0)
        fault_take(FAULT_CPU_FP_DISABLED);
}

static void execute_fp_check(cpu_t *cpu)
{
    check_vfp_enabled(cpu);

    FPCCR_t fpccr = scb_fp_get_fpccr(cpu->scb_fp);

    // We ignore FPCCR.LSPEN because we never use lazy stacking

    if (fpccr.ASPEN && !cpu->control.FPCA)
    {
        // cpu->control.FPCA = 1;
    }
}

static void push_stack(cpu_t *cpu, arm_exception ex, bool sync)
{
    // Copied as closely as possible from the ARMv7-M Architecture Reference Manual's pseudocode at B1.5.6

    uint32_t framesize;
    uint32_t forcealign;

    if (cpu->control.FPCA)
    {
        framesize = 0x68;
        forcealign = 1;
    }
    else
    {
        framesize = 0x20;
        forcealign = scb_get_ccr(cpu->scb).STKALIGN;
    }

    uint32_t spmask = ~(forcealign << 2);

    uint32_t frameptralign, frameptr;

    if (cpu->control.SPSEL && cpu->mode == ARM_MODE_THREAD)
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

    memory_map_write_traced(cpu, frameptr, cpu->core_regs[ARM_REG_R0], SIZE_WORD);
    memory_map_write_traced(cpu, frameptr + 0x4, cpu->core_regs[ARM_REG_R1], SIZE_WORD);
    memory_map_write_traced(cpu, frameptr + 0x8, cpu->core_regs[ARM_REG_R2], SIZE_WORD);
    memory_map_write_traced(cpu, frameptr + 0xC, cpu->core_regs[ARM_REG_R3], SIZE_WORD);
    memory_map_write_traced(cpu, frameptr + 0x10, cpu->core_regs[ARM_REG_R12], SIZE_WORD);
    memory_map_write_traced(cpu, frameptr + 0x14, cpu->core_regs[ARM_REG_LR], SIZE_WORD);
    memory_map_write_traced(cpu, frameptr + 0x18, exception_return_address(cpu, ex, sync), SIZE_WORD);
    memory_map_write_traced(cpu, frameptr + 0x1C, (xpsr & ~(1 << 9)) | (frameptralign << 9), SIZE_WORD);

    if (cpu->control.FPCA)
    {
        // Ignore FPCCR.LSPEN and always save stack

        check_vfp_enabled(cpu);
        uint32_t ptr = frameptr + 0x20;

        for (size_t i = 0; i < 8; i++)
        {
            memory_map_write_traced(cpu, ptr, cpu->d[i].lower, SIZE_WORD);
            memory_map_write_traced(cpu, ptr + 4, cpu->d[i].upper, SIZE_WORD);

            ptr += 8;
        }

        memory_map_write_traced(cpu, ptr, cpu_reg_read(cpu, ARM_REG_FPSCR), SIZE_WORD);
    }

    if (cpu->mode == ARM_MODE_HANDLER)
        cpu_reg_write(cpu, ARM_REG_LR, x(FFFF, FFE1) | (~cpu->control.FPCA << 4));
    else
        cpu_reg_write(cpu, ARM_REG_LR, x(FFFF, FFE9) | (~cpu->control.FPCA << 4) | (cpu->control.SPSEL << 2));
}

static void pop_stack(cpu_t *cpu, uint32_t sp, uint32_t exc_return)
{
    uint32_t framesize;
    uint32_t forcealign;

    uint32_t frametype = exc_return & (1 << 4);

    if (frametype == 0)
    {
        framesize = 0x68;
        forcealign = 1;
    }
    else
    {
        framesize = 0x20;
        forcealign = scb_get_ccr(cpu->scb).STKALIGN;
    }

    cpu->core_regs[ARM_REG_R0] = memory_map_read_traced_word(cpu, sp);
    cpu->core_regs[ARM_REG_R1] = memory_map_read_traced_word(cpu, sp + 0x4);
    cpu->core_regs[ARM_REG_R2] = memory_map_read_traced_word(cpu, sp + 0x8);
    cpu->core_regs[ARM_REG_R3] = memory_map_read_traced_word(cpu, sp + 0xC);
    cpu->core_regs[ARM_REG_R12] = memory_map_read_traced_word(cpu, sp + 0x10);
    cpu->core_regs[ARM_REG_LR] = memory_map_read_traced_word(cpu, sp + 0x14);
    cpu_reg_write(cpu, ARM_REG_PC, memory_map_read_traced_word(cpu, sp + 0x18) | 1);
    uint32_t psr = memory_map_read_traced_word(cpu, sp + 0x1C);

    LOG_CPU_EX("Returning from exception to 0x%08X", cpu->core_regs[ARM_REG_PC]);

    if (frametype == 0)
    {
        // Ignore LSPACT

        check_vfp_enabled(cpu);

        uint32_t ptr = sp + 0x20;

        for (size_t i = 0; i < 8; i++)
        {
            cpu->d[i].lower = memory_map_read_traced_word(cpu, ptr);
            cpu->d[i].upper = memory_map_read_traced_word(cpu, ptr + 4);

            ptr += 8;
        }

        cpu_reg_write(cpu, ARM_REG_FPSCR, memory_map_read_traced_word(cpu, ptr));
    }

    cpu->control.FPCA = frametype == 0;

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

    default:
        fault_take(FAULT_CPU_INVALID_EXCEPTION_RETURN);
    }

    cpu_sysreg_write(cpu, ARM_SYSREG_XPSR, psr & 0xFF0FFDFF, true);
}

static void exception_taken(cpu_t *cpu, arm_exception ex)
{
#if ASSERT_EXCEPTION_REGISTERS
    for (size_t i = 0; i < sizeof(check_exc_registers) / sizeof(arm_reg); i++)
    {
        arm_reg reg = check_exc_registers[i];
        cpu->exception_regs[i][cpu->exception_regs_count] = cpu->core_regs[reg];
    }
    cpu->exception_regs_count++;
#endif

    cpu_jump_exception(cpu, ex);

    cpu->mode = ARM_MODE_HANDLER;

    cpu->xpsr.ipsr = ex;
    cpu->itstate.value = 0;

    cpu->control.FPCA = 0;
    cpu->control.SPSEL = 0;

    exception_set_active(cpu, ex, true);

    // TODO: SCS_UpdateStatusRegs
}

static void exception_entry(cpu_t *cpu, arm_exception ex, bool sync)
{
    LOG_CPU_EX("Entering exception %d from 0x%08X", ex, cpu->core_regs[ARM_REG_PC]);

    DO_RUNLOG(runlog_exception_enter(cpu->runlog, ex));

    push_stack(cpu, ex, sync);
    exception_taken(cpu, ex);

    cpu_exception_clear_pending(cpu, ex);
}

static void exception_return(cpu_t *cpu, uint32_t exc_return)
{
    assert(cpu->mode == ARM_MODE_HANDLER);

    arm_exception returning_exception_number = cpu->xpsr.ipsr;

    DO_RUNLOG(runlog_exception_exit(cpu->runlog, returning_exception_number));

    assert(cpu->exceptions[returning_exception_number].active);

    uint32_t frameptr;

    switch (exc_return & 0xF)
    {
    case 1:
        frameptr = cpu->sp_main;
        cpu->mode = ARM_MODE_HANDLER;
        cpu->control.SPSEL = 0;
        break;

    case 9:
        // TODO: Check NestedActivation and CCR.NONBASETHRDENA

        frameptr = cpu->sp_main;
        cpu->mode = ARM_MODE_THREAD;
        cpu->control.SPSEL = 0;
        break;

    case 13:
        // TODO: Check NestedActivation and CCR.NONBASETHRDENA

        frameptr = cpu->sp_process;
        cpu->mode = ARM_MODE_THREAD;
        cpu->control.SPSEL = 1;
        break;

    default:
        fault_take(FAULT_CPU_INVALID_EXCEPTION_RETURN);
    }

    exception_set_active(cpu, returning_exception_number, false);

    if (cpu->xpsr.ipsr != 2)
        cpu->faultmask = 0;

    pop_stack(cpu, frameptr, exc_return);

#if ASSERT_EXCEPTION_REGISTERS
    if (returning_exception_number != ARM_EXC_SVC && returning_exception_number != ARM_EXC_PENDSV)
    {
        uint32_t *before_regs = cpu->exception_regs[--cpu->exception_regs_count];

        bool mismatched = false;

        for (size_t i = 0; i < sizeof(check_exc_registers) / sizeof(arm_reg); i++)
        {
            arm_reg reg = check_exc_registers[i];

            if (cpu->core_regs[reg] != before_regs[i])
            {
                fprintf(stderr, "Register %d mismatch: 0x%08X != 0x%08X\n", reg, cpu->core_regs[reg], before_regs[i]);
                mismatched = true;
            }
        }

        if (mismatched)
            abort();
    }
#endif

    update_execution_priority(cpu);

    arm_exception pending = exception_get_pending(cpu);
    if (pending != 0)
    {
        exception_entry(cpu, pending, false);
    }
}

#if ENABLE_RUNLOG
void cpu_set_runlog(cpu_t *cpu, runlog_t *runlog)
{
    cpu->runlog = runlog;
}
#endif

void cpu_set_branch_cb(cpu_t *cpu, branch_cb_t branch_cb, void *userdata)
{
    cpu->branch_cb = branch_cb;
    cpu->branch_cb_userdata = userdata;
}

static void do_load(cpu_t *cpu, cs_arm *detail, byte_size_t size, bool sign_extend)
{
    assert(detail->op_count == 2 || detail->op_count == 3);
    assert(detail->operands[0].type == ARM_OP_REG);
    assert(detail->operands[1].type == ARM_OP_MEM);
    assert(size == 1 || size == 2 || size == 4);

    uint32_t address = cpu_reg_read(cpu, detail->operands[1].mem.base);
    uint32_t offset;

    if (detail->operands[1].mem.base == ARM_REG_PC)
        address &= x(FFFF, FFFC); // Align PC value when used as a base register according to A5.1.2

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

    uint32_t offsetAddr = address + (detail->post_index ? 0 : offset);
    uint32_t value;

    switch (size)
    {
    case SIZE_WORD:
        value = memory_map_read_traced_word(cpu, offsetAddr);
        break;

    case SIZE_HALFWORD:
        value = memory_map_read_traced_halfword(cpu, offsetAddr);
        break;

    case SIZE_BYTE:
        value = memory_map_read_traced_byte(cpu, offsetAddr);
        break;

    default:
        abort();
    }

    if (sign_extend)
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

    DO_RUNLOG(runlog_record_memory_load(cpu->runlog, offsetAddr, value, runlog_reg(detail->operands[0].reg), size));

    if (detail->writeback)
        cpu_reg_write(cpu, detail->operands[1].mem.base, address + offset);

    cpu_reg_write(cpu, detail->operands[0].reg, value);
}

static void do_store(cpu_t *cpu, cs_arm *detail, byte_size_t size, bool dual)
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

    memory_map_write_traced(cpu, address, value, size);

    DO_RUNLOG(runlog_record_memory_store(cpu->runlog, runlog_reg(detail->operands[0].reg), value, address, size));

    if (dual)
    {
        value = cpu_reg_read(cpu, detail->operands[1].reg);
        memory_map_write_traced(cpu, address + 4, value, size);
    }

    if (detail->writeback)
        cpu_reg_write(cpu, mem_op->mem.base, offset_addr);
}

static void add_arm_memregs(cpu_t *cpu, size_t priority_bits)
{
    NEW_PERIPH(cpu, DWT, dwt, dwt, x(E000, 1000), 0x1000, cpu->state_store);
    NEW_PERIPH(cpu, SCB, scb, scb, x(E000, ED00), 0x90, cpu, cpu->state_store);
    NEW_PERIPH(cpu, DCB, dcb, dcb, x(E000, EDF0), 0x110, cpu->state_store);
    NEW_PERIPH(cpu, SCB_FP, scb_fp, scb_fp, x(E000, EF00), 0x90, cpu->state_store);
    NEW_PERIPH(cpu, NVIC, nvic, nvic, x(E000, E100), 0xBFF, cpu, cpu->state_store, priority_bits);
}

static void do_stmdb(cpu_t *cpu, arm_reg base_reg, bool writeback, cs_arm_op *reg_operands, uint8_t reg_count)
{
    uint32_t address = cpu_reg_read(cpu, base_reg) - 4 * reg_count;

    if (writeback)
        cpu_reg_write(cpu, base_reg, address);

    for (size_t i = 0; i < reg_count; i++)
    {
        assert(reg_operands[i].type == ARM_OP_REG);

        uint32_t value = cpu_reg_read(cpu, reg_operands[i].reg);

        memory_map_write_traced(cpu, address, value, SIZE_WORD);

        DO_RUNLOG(runlog_record_memory_store(cpu->runlog, runlog_reg(reg_operands[i].reg), value, address, SIZE_WORD));

        address += 4;
    }
}

static inline void decode_arithmetic(cpu_t *cpu, cs_insn *i, uint32_t *op0_val, uint32_t *op1_val, bool *carry)
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
        *op1_val = load_operand(cpu, op2, carry);
    }
}

cpu_t *cpu_new(const uint8_t *program, size_t program_size, memory_map_t *mem, state_store_t *store, size_t max_external_interrupts, size_t priority_bits)
{
    cpu_t *cpu = calloc(1, sizeof(cpu_t));
    cpu->state_store = store;
    cpu->program = program;
    cpu->program_size = program_size;
    cpu->mem = mem;
    cpu->exception_count = 16 + max_external_interrupts;

    state_store_register(store, STATE_KEY_CPU, cpu, sizeof(struct state));

    add_arm_memregs(cpu, priority_bits);

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
    cpu->control.value = 0;

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

    update_execution_priority(cpu);

    cpu_jump_exception(cpu, ARM_EXC_RESET);

    DO_RUNLOG(runlog_record_reset(cpu->runlog, get_runlog_regs(cpu)));
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
                fault_take(FAULT_CPU_INVALID_INSTRUCTION);
            }
        }

        return *insn;
    }

    uint32_t code = memory_map_read_traced_word(cpu, pc);

    if (cpu->last_external_inst)
        cs_free(cpu->last_external_inst, 1);

    // TODO: Reuse the same buffer for all external instructions using cs_disasm_iter
    size_t n = cs_disasm(cpu->cs, (const uint8_t *)&code, sizeof(code), pc, 1, &cpu->last_external_inst);

    if (n == 0)
    {
        fprintf(stderr, "Failed to disassemble code at 0x%08X\n", pc);
        fault_take(FAULT_CPU_INVALID_INSTRUCTION);
    }

    assert(n == 1);

    return cpu->last_external_inst;
}

#define USE_CYCLES(n) \
    do                \
    {                 \
        cycles = n;   \
    } while (0)

static int execute_instruction(cpu_t *cpu, cs_insn *i, uint32_t next_pc)
{
    int cycles = 0;

    uint32_t op0, op1, value, address;
    cs_arm *detail = &i->detail->arm;

    LOG_CPU_INST("%s %s", i->mnemonic, i->op_str);

    if (cpu->sleep_fuel)
        cpu->sleep_fuel--;

    switch (i->id)
    {
    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
    case ARM_INS_IT:
        break;
    default:
        if (!condition_passed(cpu, i))
        {
            it_advance(cpu);
            return 0; // TODO: Do skipped instructions use cycles?
        }

        break;
    }

    bool update_flags = detail->update_flags;
    if (cpu->must_advance_it && i->size == 2 && i->id != ARM_INS_CMP && i->id != ARM_INS_CMN && i->id != ARM_INS_TST)
        update_flags = false;

    bool carry = false, overflow = false;

    switch (i->id)
    {
    case ARM_INS_ADC:
        USE_CYCLES(1);

        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        if (i->size == 4)
        {
            // Fix Capstone bug where update_flags is always true on ADC T2
            update_flags = i->bytes[0] & (1 << 4);
        }

        carry = cpu->xpsr.apsr_c;
        value = AddWithCarry(op0, op1, &carry, &overflow);

        store_operand(cpu, &detail->operands[0], value, SIZE_WORD);

        UPDATE_NZCV;
        break;

    case ARM_INS_ADD:
        USE_CYCLES(1 + (detail->operands[0].reg == ARM_REG_PC ? 1 : 0));

        assert(detail->operands[0].type == ARM_OP_REG);
        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        // TODO: Make sure this implements ADR correctly
        if (detail->op_count == 3 && detail->operands[1].reg == ARM_REG_PC)
        {
            op0 = ALIGN4(op0);
        }

        carry = false;
        value = AddWithCarry(op0, op1, &carry, &overflow);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZCV;
        break;

    case ARM_INS_ADR:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_IMM);

        value = ALIGN4(cpu_reg_read(cpu, ARM_REG_PC));

        if (detail->operands[1].subtracted)
            value -= detail->operands[1].imm;
        else
            value += detail->operands[1].imm;

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_AND:
        USE_CYCLES(1);

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
        USE_CYCLES(1);

        op0 = OPERAND_REG(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = cpu->xpsr.apsr_c;
        value = Shift_C(op0, ARM_SFT_ASR, op1 & 0xFF, &carry);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_B:
    case ARM_INS_BX:
        USE_CYCLES(2);

        assert(detail->op_count == 1);

        BRANCH_WRITE_PC(cpu, OPERAND(0) | 1);
        break;

    case ARM_INS_BFC:
    {
        USE_CYCLES(1);

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
        USE_CYCLES(1);

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
        USE_CYCLES(1);

        decode_arithmetic(cpu, i, &op0, &op1, &carry);

        value = op0 & ~op1;
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_BL:
    case ARM_INS_BLX:
        USE_CYCLES(2);

        assert(detail->op_count == 1);

        cpu_reg_write(cpu, ARM_REG_LR, next_pc | 1);
        BRANCH_WRITE_PC(cpu, OPERAND(0) | 1);
        break;

    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        op0 = OPERAND_REG(0);

        if ((op0 == 0) == (i->id == ARM_INS_CBZ))
        {
            op1 = OPERAND_IMM(1);

            USE_CYCLES(1);
            BRANCH_WRITE_PC(cpu, op1 | 1);
        }
        break;

    case ARM_INS_CLZ:
        USE_CYCLES(1);

        assert(detail->op_count == 2);

        op0 = OPERAND_REG(0);
        op1 = OPERAND_REG(1);

        value = op1 == 0 ? 32 : __builtin_clz(op1);
        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_CMN:
        USE_CYCLES(1);

        assert(detail->update_flags);
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg);
        op1 = OPERAND(1);

        value = AddWithCarry(op0, op1, &carry, &overflow);

        UPDATE_NZCV
        break;

    case ARM_INS_CMP:
        USE_CYCLES(1);

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
        USE_CYCLES(1);

        if (is_privileged(cpu))
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

                if ((detail->cps_flag & ARM_CPSFLAG_F) != 0 && cpu->execution_priority > -1)
                    SET(cpu->faultmask, 0);
            }

            update_execution_priority(cpu);
        }
        break;

    case ARM_INS_DBG:
    case ARM_INS_DMB:
    case ARM_INS_DSB:
    case ARM_INS_ISB:
    case ARM_INS_NOP:
    case ARM_INS_PLD:
    case ARM_INS_PLI:
        USE_CYCLES(1);
        // Do nothing
        break;

    case ARM_INS_EOR:
        USE_CYCLES(1);

        decode_arithmetic(cpu, i, &op0, &op1, &carry);

        value = op0 ^ op1;
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_FCONSTS:
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_FP);

        if (detail->vector_data == ARM_VECTORDATA_F64)
        {
            USE_CYCLES(2);

            cpu->d[detail->operands[0].reg - ARM_REG_D0].f_value = detail->operands[1].fp;
        }
        else
        {
            USE_CYCLES(1);

            assert(detail->vector_data == ARM_VECTORDATA_F32);

            float32_t value = FLOAT32_F(detail->operands[1].fp);
            cpu_reg_write(cpu, detail->operands[0].reg, value.i);
        }

        break;

    case ARM_INS_HINT:
        USE_CYCLES(1);

        if (i->size == 2 && i->bytes[0] == 0x20 && i->bytes[1] == 0xBF)
        {
            // WFE
            cpu->sleep_fuel = 10;
        }
        break;

    case ARM_INS_IT:
        USE_CYCLES(1);

        assert(i->size == 2);
        assert(i->bytes[1] == 0xBF);

#if ENABLE_LOG_CPU_IT
        LOG("IT", "Entering IT block, ITSTATE: 0x%X", i->bytes[0]);
#endif

        cpu->itstate.value = i->bytes[0];
        break;

    case ARM_INS_LDM:
        USE_CYCLES(1 + detail->op_count - 1);

        assert(detail->op_count >= 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        address = cpu_reg_read(cpu, detail->operands[0].reg);

        for (int n = 0; n < detail->op_count - 1; n++)
        {
            value = memory_map_read_traced_word(cpu, address);
            address += 4;

            cpu_reg_write(cpu, detail->operands[n + 1].reg, value);
        }

        // TODO: Check if registers<n> == '0', else don't write back
        if (detail->writeback)
            cpu_reg_write(cpu, detail->operands[0].reg, address);
        break;

    case ARM_INS_LDMDB:
        USE_CYCLES(1 + detail->op_count - 1);

        assert(detail->op_count >= 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg) - 4 * (detail->op_count - 1);
        address = op0;

        for (int n = 0; n < detail->op_count - 1; n++)
        {
            value = memory_map_read_traced_word(cpu, address);
            address += 4;

            cpu_reg_write(cpu, detail->operands[n + 1].reg, value);
        }

        // TODO: Check if registers<n> == '0', else don't write back
        if (detail->writeback)
            cpu_reg_write(cpu, detail->operands[0].reg, op0);
        break;

    case ARM_INS_LDR:
    case ARM_INS_LDREX:
        USE_CYCLES(2);
        do_load(cpu, detail, SIZE_WORD, false);
        break;

    case ARM_INS_LDRB:
    case ARM_INS_LDREXB:
        USE_CYCLES(2);
        do_load(cpu, detail, SIZE_BYTE, false);
        break;

    case ARM_INS_LDRSB:
        USE_CYCLES(2);
        do_load(cpu, detail, SIZE_BYTE, true);
        break;

    case ARM_INS_LDRD:
        USE_CYCLES(3);

        value = mem_operand_address(cpu, &detail->operands[2]);

        store_operand(cpu, &detail->operands[0], memory_map_read_traced_word(cpu, value), SIZE_WORD);
        store_operand(cpu, &detail->operands[1], memory_map_read_traced_word(cpu, value + 4), SIZE_WORD);
        break;

    case ARM_INS_LDRH:
        USE_CYCLES(2);
        do_load(cpu, detail, SIZE_HALFWORD, false);
        break;

    case ARM_INS_LDRSH:
        USE_CYCLES(2);
        do_load(cpu, detail, SIZE_HALFWORD, true);
        break;

    case ARM_INS_LSL:
        USE_CYCLES(2);

        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = cpu->xpsr.apsr_c;
        value = Shift_C(op0, ARM_SFT_LSL, op1, &carry);

        store_operand(cpu, &detail->operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_LSR:
        USE_CYCLES(1);

        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = cpu->xpsr.apsr_c;
        value = Shift_C(op0, ARM_SFT_LSR, op1 & 0xFF, &carry);

        store_operand(cpu, &detail->operands[0], value, SIZE_WORD);

        UPDATE_NZC;
        break;

    case ARM_INS_MLA:
    case ARM_INS_MLS:
        USE_CYCLES(2);

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
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        value = OPERAND(1);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZ; // FIXME: Carry should also be set sometimes but it seems like Capstone doesn't expose it
        break;

    case ARM_INS_MOVT:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_IMM);

        value = cpu_reg_read(cpu, detail->operands[0].reg) & 0xFFFF;
        value |= detail->operands[1].imm << 16;

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_MRS:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_SYSREG);

        value = cpu_sysreg_read(cpu, detail->operands[1].reg);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_MSR:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_SYSREG);
        assert(detail->operands[1].type == ARM_OP_REG);

        value = cpu_reg_read(cpu, detail->operands[1].reg);

        cpu_sysreg_write(cpu, detail->operands[0].reg, value, false);
        break;

    case ARM_INS_MUL:
        USE_CYCLES(1);

        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND_REG(2);

        value = op0 * op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZ
        break;

    case ARM_INS_MVN:
        USE_CYCLES(1);

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
        USE_CYCLES(1);

        decode_arithmetic(cpu, i, &op0, &op1, &carry);

        value = op0 | ~op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_ORR:
        USE_CYCLES(1);

        decode_arithmetic(cpu, i, &op0, &op1, &carry);

        value = op0 | op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_PKHBT:
    case ARM_INS_PKHTB:
        USE_CYCLES(1);

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
        USE_CYCLES(1 + detail->op_count);

        op0 = cpu_reg_read(cpu, ARM_REG_SP);

        cpu_reg_write(cpu, ARM_REG_SP, op0 + 4 * detail->op_count);

        for (int n = 0; n < detail->op_count; n++)
        {
            value = memory_map_read_traced_word(cpu, op0);

            store_operand(cpu, &detail->operands[n], value, SIZE_WORD);

            op0 += 4;
        }
        break;

    case ARM_INS_PUSH:
        USE_CYCLES(1 + detail->op_count);
        do_stmdb(cpu, ARM_REG_SP, true, &detail->operands[0], detail->op_count);
        break;

    case ARM_INS_RBIT:
        USE_CYCLES(1);

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
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);

        value = ((op0 & 0xFF) << 24) | ((op0 & 0xFF00) << 8) | ((op0 & 0xFF0000) >> 8) | ((op0 & 0xFF000000) >> 24);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_REV16:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[1].reg);

        value = ((op0 & 0xFF) << 8) | ((op0 & 0xFF00) >> 8) | ((op0 & 0xFF0000) << 8) | ((op0 & 0xFF000000) >> 8);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_REVSH:
        USE_CYCLES(1);

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
        USE_CYCLES(1);

        op0 = OPERAND_REG(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = cpu->xpsr.apsr_c;
        value = Shift_C(op0, ARM_SFT_ROR, op1 & 0xFF, &carry);

        cpu_reg_write(cpu, detail->operands[0].reg, value);

        UPDATE_NZC;
        break;

    case ARM_INS_RRX:
        USE_CYCLES(1);

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
        USE_CYCLES(1);

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
        USE_CYCLES(1);

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
        USE_CYCLES(1);

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
        USE_CYCLES(1);

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
        USE_CYCLES(1);

        decode_arithmetic(cpu, i, &op0, &op1, &carry);

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
        USE_CYCLES(1);

        op1 = OPERAND(1);
        uint32_t lsb = OPERAND(2);
        uint32_t width = OPERAND(3);

        uint32_t mask = 1 << (width - 1);

        assert(lsb + width <= 32);

        value = (op1 >> lsb) & ((1 << width) - 1);
        value = (value ^ mask) - mask; // Sign extend https://stackoverflow.com/a/17719010

        store_operand(cpu, &detail->operands[0], value, SIZE_WORD);
        break;
    }

    case ARM_INS_SDIV:
    case ARM_INS_UDIV:
        USE_CYCLES(6); // 2 to 12

        assert(detail->op_count == 2 || detail->op_count == 3);

        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->op_count < 3 || detail->operands[2].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[detail->op_count == 3 ? 1 : 0].reg);
        op1 = cpu_reg_read(cpu, detail->operands[detail->op_count == 3 ? 2 : 1].reg);

        // TODO: Exception if op1 is zero
        assert_fault(op1 != 0, FAULT_CPU_DIVIDE_BY_ZERO);

        if (i->id == ARM_INS_SDIV)
            value = (int32_t)op0 / (int32_t)op1;
        else
            value = op0 / op1;

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_SEL:
        USE_CYCLES(1);

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

    case ARM_INS_SMLABB:
    case ARM_INS_SMLABT:
    case ARM_INS_SMLATB:
    case ARM_INS_SMLATT:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND_REG(2);

        int16_t a, b;

        if (i->id == ARM_INS_SMLABB || i->id == ARM_INS_SMLABT)
            a = op0 & 0xFFFF;
        else
            a = (op0 >> 16) & 0xFFFF;

        if (i->id == ARM_INS_SMLABB || i->id == ARM_INS_SMLATB)
            b = op1 & 0xFFFF;
        else
            b = (op1 >> 16) & 0xFFFF;

        int32_t result = (int32_t)a * b + OPERAND_REG(3);

        cpu_reg_write(cpu, detail->operands[0].reg, result);
        break;
    }

    case ARM_INS_SMLAL:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 4);

        op0 = OPERAND_REG(2);
        op1 = OPERAND_REG(3);

        int64_t acc_lo = OPERAND_REG(0);
        int64_t acc_hi = OPERAND_REG(1);

        uint64_t result = (int64_t)(int32_t)op0 * (int64_t)(int32_t)op1 + ((acc_hi << 32) | acc_lo);

        cpu_reg_write(cpu, detail->operands[0].reg, result & x(FFFF, FFFF));
        cpu_reg_write(cpu, detail->operands[1].reg, result >> 32);

        break;
    }

    case ARM_INS_SMULBB:
    case ARM_INS_SMULBT:
    case ARM_INS_SMULTB:
    case ARM_INS_SMULTT:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND_REG(2);

        int16_t a, b;

        if (i->id == ARM_INS_SMULBB || i->id == ARM_INS_SMULBT)
            a = op0 & 0xFFFF;
        else
            a = (op0 >> 16) & 0xFFFF;

        if (i->id == ARM_INS_SMULBB || i->id == ARM_INS_SMULTB)
            b = op1 & 0xFFFF;
        else
            b = (op1 >> 16) & 0xFFFF;

        int32_t result = (int32_t)a * b;

        cpu_reg_write(cpu, detail->operands[0].reg, result);
        break;
    }

    case ARM_INS_SMULL:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        uint64_t result = (int64_t)(int32_t)OPERAND_REG(2) * (int64_t)(int32_t)OPERAND_REG(3);

        cpu_reg_write(cpu, detail->operands[0].reg, result & x(FFFF, FFFF));
        cpu_reg_write(cpu, detail->operands[1].reg, (result >> 32) & x(FFFF, FFFF));
        break;
    }

    case ARM_INS_STM:
        USE_CYCLES(detail->op_count);

        assert(detail->op_count >= 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg);

        for (size_t n = 1; n < detail->op_count; n++)
        {
            assert(detail->operands[n].type == ARM_OP_REG);

            memory_map_write_traced(cpu, op0, cpu_reg_read(cpu, detail->operands[n].reg), SIZE_WORD);

            op0 += 4;
        }

        if (detail->writeback)
            cpu_reg_write(cpu, detail->operands[0].reg, op0);
        break;

    case ARM_INS_STR:
        USE_CYCLES(2);
        do_store(cpu, detail, SIZE_WORD, false);
        break;

    case ARM_INS_STRB:
        USE_CYCLES(2);
        do_store(cpu, detail, SIZE_BYTE, false);
        break;

    case ARM_INS_STRD:
        USE_CYCLES(2);
        do_store(cpu, detail, SIZE_WORD, true);
        break;

    case ARM_INS_STREX:
    case ARM_INS_STREXB:
    case ARM_INS_STREXH:
        USE_CYCLES(2);

        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_MEM);

        op0 = mem_operand_address(cpu, &detail->operands[2]);

        cpu_reg_write(cpu, detail->operands[0].reg, 0);
        memory_map_write_traced(cpu, op0, cpu_reg_read(cpu, detail->operands[1].reg),
                                i->id == ARM_INS_STREXB ? SIZE_BYTE : i->id == ARM_INS_STREXH ? SIZE_HALFWORD
                                                                                              : SIZE_WORD);
        break;

    case ARM_INS_STRH:
        USE_CYCLES(2);
        do_store(cpu, detail, SIZE_HALFWORD, false);
        break;

    case ARM_INS_STMDB:
        USE_CYCLES(1 + detail->op_count - 1);
        do_stmdb(cpu, detail->operands[0].reg, detail->writeback, &detail->operands[1], detail->op_count - 1);
        break;

    case ARM_INS_SUB:
        USE_CYCLES(1);

        op0 = OPERAND(detail->op_count == 3 ? 1 : 0);
        op1 = OPERAND(detail->op_count == 3 ? 2 : 1);

        carry = true;
        value = AddWithCarry(op0, ~op1, &carry, &overflow);

        store_operand(cpu, &detail->operands[0], value, SIZE_WORD);

        UPDATE_NZCV
        break;

    case ARM_INS_SVC:
        USE_CYCLES(1);
        cpu_exception_set_pending(cpu, ARM_EXC_SVC);
        break;

    case ARM_INS_SXTAB:
        USE_CYCLES(1);

        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND(2);

        value = op0 + SIGNEXTEND8_32(op1);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_SXTAH:
        USE_CYCLES(1);

        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND(2);

        value = op0 + SIGNEXTEND16_32(op1);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_SXTB:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        value = SIGNEXTEND8_32(OPERAND(1));

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_SXTH:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        value = SIGNEXTEND16_32(OPERAND(1));

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_TBB:
    case ARM_INS_TBH:
        USE_CYCLES(3);

        assert(detail->op_count == 1);
        assert(detail->operands[0].type == ARM_OP_MEM);

        op0 = mem_operand_address(cpu, &detail->operands[0]);
        value = memory_map_read_traced_word(cpu, op0) & (i->id == ARM_INS_TBB ? 0xFF : 0xFFFF);

        cpu_reg_write(cpu, ARM_REG_PC, (cpu_reg_read(cpu, ARM_REG_PC) + value * 2) | 1);
        break;

    case ARM_INS_TEQ:
    case ARM_INS_TST:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);

        carry = cpu->xpsr.apsr_c;

        if (detail->operands[1].type == ARM_OP_IMM)
            carry = CalculateThumbExpandCarry(i->bytes, detail->operands[1].imm, carry);

        op0 = cpu_reg_read(cpu, detail->operands[0].reg);
        op1 = OPERAND_C(1);

        if (i->id == ARM_INS_TEQ)
            value = op0 ^ op1;
        else
            value = op0 & op1;

        UPDATE_NZC
        break;

    case ARM_INS_UADD8:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND_REG(2);

        uint16_t sum1 = (op0 & 0xFF) + (op1 & 0xFF);
        uint16_t sum2 = ((op0 >> 8) & 0xFF) + ((op1 >> 8) & 0xFF);
        uint16_t sum3 = ((op0 >> 16) & 0xFF) + ((op1 >> 16) & 0xFF);
        uint16_t sum4 = ((op0 >> 24) & 0xFF) + ((op1 >> 24) & 0xFF);

        cpu_reg_write(cpu, detail->operands[0].reg,
                      ((sum4 & 0xFF) << 24) |
                          ((sum3 & 0xFF) << 16) |
                          ((sum2 & 0xFF) << 8) |
                          (sum1 & 0xFF));

        cpu->xpsr.apsr_ge0 = sum1 >= 0x100;
        cpu->xpsr.apsr_ge1 = sum2 >= 0x100;
        cpu->xpsr.apsr_ge2 = sum3 >= 0x100;
        cpu->xpsr.apsr_ge3 = sum4 >= 0x100;
        break;
    }

    case ARM_INS_UBFX:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);

        op1 = OPERAND_REG(1);
        uint32_t lsb = OPERAND_IMM(2);
        uint32_t width = OPERAND_IMM(3);

        assert(lsb + width <= 32);

        value = (op1 >> lsb) & ((1 << width) - 1);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;
    }

    case ARM_INS_UMLAL:
    case ARM_INS_UMULL:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 4);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        uint64_t result = (uint64_t)OPERAND_REG(2) * (uint64_t)OPERAND_REG(3);

        if (i->id == ARM_INS_UMLAL)
            result += ((uint64_t)OPERAND_REG(1) << 32) | (uint64_t)OPERAND_REG(0);

        cpu_reg_write(cpu, detail->operands[0].reg, result & x(FFFF, FFFF));
        cpu_reg_write(cpu, detail->operands[1].reg, result >> 32);
        break;
    }

    case ARM_INS_USAT:
        USE_CYCLES(1);

        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[2].type == ARM_OP_REG);

        carry = cpu->xpsr.apsr_c;

        op0 = OPERAND_IMM(1);
        op1 = OPERAND_C(2);

        bool saturated = UnsignedSatQ(op1, op0, &value);
        cpu_reg_write(cpu, detail->operands[0].reg, value);

        if (saturated)
            cpu->xpsr.apsr_q = 1;
        break;

    case ARM_INS_UXTAH:
    case ARM_INS_UXTAB:
        USE_CYCLES(1);

        assert(detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);

        op0 = OPERAND_REG(1);
        op1 = OPERAND(2);

        value = op0 + (op1 & (i->id == ARM_INS_UXTAB ? 0xFF : 0xFFFF));

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_UXTB:
    case ARM_INS_UXTH:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        value = OPERAND(1) & (i->id == ARM_INS_UXTB ? 0xFF : 0xFFFF);

        cpu_reg_write(cpu, detail->operands[0].reg, value);
        break;

    case ARM_INS_VADD:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 2 || detail->op_count == 3);
        execute_fp_check(cpu);

        if (IS_DOUBLE(detail->operands[0]))
        {
            fault_take(FAULT_NOT_IMPLEMENTED);
        }
        else
        {
            float32_t a = FLOAT32_I(OPERAND_REG(detail->op_count == 3 ? 1 : 0));
            float32_t b = FLOAT32_I(OPERAND_REG(detail->op_count - 1));
            float32_t result = FLOAT32_F(a.f + b.f);

            cpu_reg_write(cpu, detail->operands[0].reg, result.i);
        }

        break;
    }

    case ARM_INS_VCVT:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        execute_fp_check(cpu);

        switch (detail->vector_data)
        {
        case ARM_VECTORDATA_S32F32:
        {
            float32_t val_float = FLOAT32_I(OPERAND_REG(1));
            int32_t val_int = (int32_t)ROUNDF_TO_ZERO(val_float.f);

            cpu_reg_write(cpu, detail->operands[0].reg, val_int);
            break;
        }

        case ARM_VECTORDATA_S32F64:
        {
            float64_t val_float = FLOAT64_I(OPERAND_REG(1));
            int32_t val_int = (int32_t)ROUNDD_TO_ZERO(val_float.f);

            cpu_reg_write(cpu, detail->operands[0].reg, val_int);
            break;
        }

        case ARM_VECTORDATA_U32F32:
        {
            float32_t val_float = FLOAT32_I(OPERAND_REG(1));
            uint32_t val_int = (uint32_t)ROUNDF_TO_ZERO(val_float.f);

            cpu_reg_write(cpu, detail->operands[0].reg, val_int);
            break;
        }

        case ARM_VECTORDATA_U32F64:
        {
            float64_t val_float = FLOAT64_I(OPERAND_REG(1));
            uint32_t val_int = (uint32_t)ROUNDD_TO_ZERO(val_float.f);

            cpu_reg_write(cpu, detail->operands[0].reg, val_int);
            break;
        }

        case ARM_VECTORDATA_F32S32:
        {
            int32_t val_int = OPERAND_REG(1);
            float32_t val_float = FLOAT32_F((float)val_int);

            cpu_reg_write(cpu, detail->operands[0].reg, val_float.i);
            break;
        }

        case ARM_VECTORDATA_F32U32:
        {
            uint32_t val_int = OPERAND_REG(1);
            float32_t val_float = FLOAT32_F((float)val_int);

            cpu_reg_write(cpu, detail->operands[0].reg, val_float.i);
            break;
        }

        case ARM_VECTORDATA_F64S32:
        {
            int32_t val_int = OPERAND_REG(1);
            float64_t val_float = FLOAT64_F((float)val_int);

            cpu->d[detail->operands[0].reg - ARM_REG_D0].value = val_float.i;
            break;
        }

        case ARM_VECTORDATA_F64U32:
        {
            uint32_t val_int = OPERAND_REG(1);
            float64_t val_float = FLOAT64_F((float)val_int);

            cpu->d[detail->operands[0].reg - ARM_REG_D0].value = val_float.i;
            break;
        }

        default:
            fault_take(FAULT_CPU_INVALID_INSTRUCTION);
        }
        break;

    case ARM_INS_VDIV:
    {
        USE_CYCLES(14);

        assert(detail->op_count == 3);
        execute_fp_check(cpu);

        if (IS_DOUBLE(detail->operands[0]))
        {
            fault_take(FAULT_NOT_IMPLEMENTED);
        }
        else
        {
            float32_t a = FLOAT32_I(OPERAND_REG(1));
            float32_t b = FLOAT32_I(OPERAND_REG(2));
            float32_t result = FLOAT32_F(a.f / b.f);

            cpu_reg_write(cpu, detail->operands[0].reg, result.i);
        }

        break;
    }

    case ARM_INS_VFMA:
    case ARM_INS_VFMS:
    {
        USE_CYCLES(3);

        assert(detail->op_count == 3);
        execute_fp_check(cpu);

        if (IS_DOUBLE(detail->operands[0]))
        {
            fault_take(FAULT_NOT_IMPLEMENTED);
        }
        else
        {
            float32_t a = FLOAT32_I(OPERAND_REG(1));
            float32_t b = FLOAT32_I(OPERAND_REG(2));
            float32_t c = FLOAT32_I(OPERAND_REG(0));

            float32_t result = i->id == ARM_INS_VFMA ? FLOAT32_F(a.f * b.f + c.f) : FLOAT32_F(a.f * b.f - c.f);

            cpu_reg_write(cpu, detail->operands[0].reg, result.i);
        }

        break;
    }

    case ARM_INS_VLDMIA:
    case ARM_INS_VPOP:
    {
        arm_reg reg_base;
        size_t list_start;

        if (i->id == ARM_INS_VPOP)
        {
            assert(detail->op_count >= 1);

            reg_base = ARM_REG_SP;
            list_start = 0;
        }
        else
        {
            assert(detail->op_count >= 2);
            assert(detail->operands[0].type == ARM_OP_REG);

            reg_base = detail->operands[0].reg;
            list_start = 1;
        }

        execute_fp_check(cpu);

        uint8_t reg_count = detail->op_count - list_start;

        bool single_regs = detail->operands[list_start].reg >= ARM_REG_S0 && detail->operands[list_start].reg <= ARM_REG_S31;

        USE_CYCLES(1 + (single_regs ? 1 : 2) * reg_count);

        uint32_t address = cpu_reg_read(cpu, reg_base);

        for (size_t n = list_start; n < reg_count; n++)
        {
            if (single_regs)
            {
                cpu_reg_write(cpu, detail->operands[n].reg, memory_map_read_traced_word(cpu, address));

                address += 4;
            }
            else
            {
                assert(IS_DOUBLE(detail->operands[n]));

                uint32_t word1 = memory_map_read_traced_word(cpu, address);
                uint32_t word2 = memory_map_read_traced_word(cpu, address + 4);

                cpu->d[detail->operands[n].reg - ARM_REG_D0].value = (uint64_t)word1 | ((uint64_t)word2 << 32);

                address += 8;
            }
        }

        if (detail->writeback || i->id == ARM_INS_VPOP)
            cpu_reg_write(cpu, reg_base, address);

        break;
    }

    case ARM_INS_VLDR:
    {
        USE_CYCLES(IS_DOUBLE(detail->operands[0]) ? 3 : 2);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_MEM);

        execute_fp_check(cpu);

        uint32_t base = cpu_reg_read(cpu, detail->operands[1].mem.base);
        if (detail->operands[1].mem.base == ARM_REG_PC)
            base = ALIGN4(base);

        uint32_t address = detail->operands[1].subtracted ? base - detail->operands[1].mem.disp : base + detail->operands[1].mem.disp;

        if (detail->operands[0].reg >= ARM_REG_S0 && detail->operands[0].reg <= ARM_REG_S31)
        {
            cpu_reg_write(cpu, detail->operands[0].reg, memory_map_read_traced_word(cpu, address));
        }
        else
        {
            assert(IS_DOUBLE(detail->operands[0]));

            uint32_t word1 = memory_map_read_traced_word(cpu, address);
            uint32_t word2 = memory_map_read_traced_word(cpu, address + 4);

            cpu->d[detail->operands[0].reg - ARM_REG_D0].value = (uint64_t)word1 | ((uint64_t)word2 << 32);
        }
        break;
    }

    case ARM_INS_VMOV: // TODO: Implement other variants
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        execute_fp_check(cpu);

        cpu_reg_write(cpu, detail->operands[0].reg, cpu_reg_read(cpu, detail->operands[1].reg));
        break;

    case ARM_INS_VMRS:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->operands[1].reg == ARM_REG_FPSCR);

        execute_fp_check(cpu);

        cpu_reg_write(cpu, detail->operands[0].reg, scb_fp_get_fpscr(cpu->scb_fp));
        break;

    case ARM_INS_VMSR:
        USE_CYCLES(1);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[0].reg == ARM_REG_FPSCR);
        assert(detail->operands[1].type == ARM_OP_REG);

        execute_fp_check(cpu);

        scb_fp_set_fpscr(cpu->scb_fp, cpu_reg_read(cpu, detail->operands[1].reg));
        break;

    case ARM_INS_VMUL:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 2 || detail->op_count == 3);

        execute_fp_check(cpu);

        bool is_dp = IS_DOUBLE(detail->operands[0]);

        if (is_dp)
        {
            fault_take(FAULT_NOT_IMPLEMENTED);
        }
        else
        {
            float32_t a = FLOAT32_I(OPERAND_REG(detail->op_count == 3 ? 1 : 0));
            float32_t b = FLOAT32_I(OPERAND_REG(detail->op_count - 1));
            float32_t result = FLOAT32_F(a.f * b.f);

            cpu_reg_write(cpu, detail->operands[0].reg, result.i);
        }

        break;
    }

    case ARM_INS_VNMUL:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 2 || detail->op_count == 3);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);
        assert(detail->vector_data == ARM_VECTORDATA_F32); // TODO: Support F64

        execute_fp_check(cpu);

        float32_t v1 = FLOAT32_I(OPERAND_REG(detail->op_count == 3 ? 1 : 0));
        float32_t v2 = FLOAT32_I(OPERAND_REG(detail->op_count - 1));
        float32_t result = FLOAT32_F(-(v1.f * v2.f));

        cpu_reg_write(cpu, detail->operands[0].reg, result.i);
        break;
    }

    case ARM_INS_VPUSH:
    case ARM_INS_VSTMDB:
    case ARM_INS_VSTMIA:
    {
        arm_reg reg_base;
        size_t list_start;
        bool add;

        if (i->id == ARM_INS_VPUSH)
        {
            assert(detail->op_count >= 1);

            reg_base = ARM_REG_SP;
            list_start = 0;
            add = false;
        }
        else
        {
            assert(detail->op_count >= 2);
            assert(detail->operands[0].type == ARM_OP_REG);

            reg_base = detail->operands[0].reg;
            list_start = 1;
            add = i->id == ARM_INS_VSTMIA;
        }

        execute_fp_check(cpu);

        uint8_t reg_count = detail->op_count - list_start;

        bool single_regs = detail->operands[list_start].reg >= ARM_REG_S0 && detail->operands[list_start].reg <= ARM_REG_S31;

        USE_CYCLES(1 + (single_regs ? 1 : 2) * reg_count);

        uint32_t base = cpu_reg_read(cpu, reg_base);
        uint32_t offset = (single_regs ? 4 : 8) * reg_count;
        uint32_t address = base - (add ? 0 : offset);

        if (detail->writeback || i->id == ARM_INS_VPUSH)
            cpu_reg_write(cpu, reg_base, base + (add ? offset : -offset));

        for (size_t n = list_start; n < reg_count; n++)
        {
            if (single_regs)
            {
                memory_map_write_traced(cpu, address, cpu_reg_read(cpu, detail->operands[n].reg), SIZE_WORD);

                address += 4;
            }
            else
            {
                assert(IS_DOUBLE(detail->operands[n]));

                memory_map_write_traced(cpu, address, cpu->d[detail->operands[n].reg - ARM_REG_D0].lower, SIZE_WORD);
                memory_map_write_traced(cpu, address + 4, cpu->d[detail->operands[n].reg - ARM_REG_D0].upper, SIZE_WORD);

                address += 8;
            }
        }

        break;
    }

    case ARM_INS_VSQRT:
    {
        USE_CYCLES(14);

        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_REG);

        execute_fp_check(cpu);

        float32_t val = FLOAT32_I(OPERAND_REG(1));
        float32_t result = FLOAT32_F(sqrtf(val.f));

        cpu_reg_write(cpu, detail->operands[0].reg, result.i);
        break;
    }

    case ARM_INS_VSTR:
    {
        assert(detail->op_count == 2);
        assert(detail->operands[0].type == ARM_OP_REG);
        assert(detail->operands[1].type == ARM_OP_MEM);

        execute_fp_check(cpu);

        uint32_t base = cpu_reg_read(cpu, detail->operands[1].mem.base);
        uint32_t address = detail->operands[1].subtracted ? base - detail->operands[1].mem.disp : base + detail->operands[1].mem.disp;

        if (detail->operands[0].reg >= ARM_REG_S0 && detail->operands[0].reg <= ARM_REG_S31)
        {
            USE_CYCLES(2);

            memory_map_write_traced(cpu, address, cpu_reg_read(cpu, detail->operands[0].reg), SIZE_WORD);
        }
        else
        {
            USE_CYCLES(3);

            assert(IS_DOUBLE(detail->operands[0]));

            memory_map_write_traced(cpu, address, cpu->d[detail->operands[0].reg - ARM_REG_D0].lower, SIZE_WORD);
            memory_map_write_traced(cpu, address + 4, cpu->d[detail->operands[0].reg - ARM_REG_D0].upper, SIZE_WORD);
        }
        break;
    }

    case ARM_INS_VSUB:
    {
        USE_CYCLES(1);

        assert(detail->op_count == 2 || detail->op_count == 3);
        execute_fp_check(cpu);

        if (IS_DOUBLE(detail->operands[0]))
        {
            fault_take(FAULT_NOT_IMPLEMENTED);
        }
        else
        {
            float32_t a = FLOAT32_I(OPERAND_REG(detail->op_count == 3 ? 1 : 0));
            float32_t b = FLOAT32_I(OPERAND_REG(detail->op_count - 1));
            float32_t result = FLOAT32_F(a.f - b.f);

            cpu_reg_write(cpu, detail->operands[0].reg, result.i);
        }

        break;
    }

    default:
        fprintf(stderr, "Unhandled instruction %s %s at 0x%08X\n", i->mnemonic, i->op_str, cpu->core_regs[ARM_REG_PC]);
        fault_take(FAULT_CPU_INVALID_INSTRUCTION);
    }

    if (cpu->must_advance_it)
        it_advance(cpu);

    assert(cycles > 0);

    return cycles;
}

#undef USE_CYCLES

int cpu_step(cpu_t *cpu)
{
    if (cpu->is_locked_up)
        return 0;

    arm_exception pending;

    uint32_t pc = cpu->core_regs[ARM_REG_PC];

    cs_insn *i = cpu_insn_at(cpu, pc);
    if (i == NULL)
    {
        fprintf(stderr, "Failed to find instruction at 0x%08X\n", cpu->core_regs[ARM_REG_PC]);
        fault_take(FAULT_CPU_INVALID_INSTRUCTION);
    }

    DO_RUNLOG(runlog_record_fetch(cpu->runlog, pc));

    uint32_t next = pc + i->size;

    cpu->branched = false;

    int cycles = execute_instruction(cpu, i, next);

    dwt_increment_cycle(cpu->dwt, cycles);

    DO_RUNLOG(runlog_record_execute(cpu->runlog, get_runlog_regs(cpu)));

    pending = exception_get_pending(cpu);
    if (pending != 0)
        exception_entry(cpu, pending, false);

    if (!cpu->branched)
    {
        cpu->core_regs[ARM_REG_PC] = next;
    }
    else
    {
        LOG_CPU_INST("Branched from 0x%08X to 0x%08X", pc, cpu->core_regs[ARM_REG_PC]);
    }

    return cycles;
}

uint32_t *cpu_get_sp(cpu_t *cpu)
{
    if (cpu->control.SPSEL)
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

    case ARM_REG_FPSCR:
        return scb_fp_get_fpscr(cpu->scb_fp);

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
            fault_take(FAULT_CPU_INVALID_FP_REGISTER);

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
            exception_return(cpu, value & x(0FFF, FFFF));
            break;
        }

        if ((value & 1) != 1)
        {
            // TODO: Handle better
            fprintf(stderr, "PC is not aligned\n");
            fault_take(FAULT_CPU_PC_ALIGNMENT);
        }

        if (cpu->branch_cb != NULL)
            cpu->branch_cb(cpu, cpu->core_regs[ARM_REG_PC], value & ~1, cpu->branch_cb_userdata);

        cpu->core_regs[ARM_REG_PC] = value & ~1;
        cpu->branched = true;

        break;

    case ARM_REG_SP:
        // assert(value >= x(2000, 0000)); // Stack overflow

        *cpu_get_sp(cpu) = value & x(FFFF, FFFC); // Lowest 2 bits are always zero
        break;

    case ARM_REG_FPSCR:
        scb_fp_set_fpscr(cpu->scb_fp, value);
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
            fault_take(FAULT_CPU_INVALID_FP_REGISTER);
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
        value &= ~0x600FC00; // Remove EPSR.IT bits
        value |= (cpu->itstate.value & 0x3) << 25;
        value |= (cpu->itstate.value & 0xFC) << 8;
        value |= cpu_get_top_running_exception(cpu) & 0x1FF;
        return value;
    }

    case ARM_SYSREG_MSP:
        return cpu->sp_main;

    case ARM_SYSREG_PSP:
        return cpu->sp_process;

    case ARM_SYSREG_CONTROL:
        return cpu->control.value;

    case ARM_SYSREG_FAULTMASK:
        return cpu->faultmask;

    case ARM_SYSREG_BASEPRI:
        return cpu->basepri;

    case ARM_SYSREG_PRIMASK:
        return cpu->primask;

    default:
        fprintf(stderr, "Unhandled system register %d\n", reg);
        fault_take(FAULT_CPU_INVALID_SYSREG);
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
        {
            cpu->itstate.value = ((value >> 25) & 0x3) | (((value >> 10) & 0x3F) << 2);

#if ENABLE_LOG_CPU_IT
            LOG("IT", "Updating ITSTATE from XPSR: 0x%X", cpu->itstate.value);
#endif
        }

        break;

    case ARM_SYSREG_MSP:
        cpu->sp_main = value;
        break;

    case ARM_SYSREG_PSP:
        cpu->sp_process = value;
        break;

    case ARM_SYSREG_CONTROL:
        cpu->control.value = value;
        break;

    case ARM_SYSREG_FAULTMASK:
        cpu->faultmask = value;
        update_execution_priority(cpu);
        break;

    case ARM_SYSREG_BASEPRI:
        cpu->basepri = value;
        update_execution_priority(cpu);
        break;

    case ARM_SYSREG_PRIMASK:
        cpu->primask = value;
        update_execution_priority(cpu);
        break;

    default:
        fprintf(stderr, "Unhandled system register %d\n", reg);
        fault_take(FAULT_CPU_INVALID_SYSREG);
    }
}

memory_map_t *cpu_mem(cpu_t *cpu)
{
    return cpu->mem;
}

bool cpu_mem_read(cpu_t *cpu, uint32_t addr, uint8_t *value)
{
    if (!memory_map_get_region(cpu->mem, addr))
        return false;

    *value = memory_map_read_traced_word(cpu, addr);
    return true;
}

bool cpu_mem_write(cpu_t *cpu, uint32_t addr, uint8_t value)
{
    if (!memory_map_get_region(cpu->mem, addr))
        return false;

    memory_map_write_traced(cpu, addr, value, SIZE_BYTE);
    return true;
}

void cpu_jump_exception(cpu_t *cpu, arm_exception ex)
{
    uint32_t vtor = scb_get_vtor_tbloff(cpu->scb);
    uint32_t vector_addr = vtor + ex * 4;

    if (vector_addr >= cpu->program_size)
        enter_lockup(cpu);
    else
        cpu_reg_write(cpu, ARM_REG_PC, READ_UINT32(cpu->program, vector_addr));
}

int16_t cpu_get_exception_priority(cpu_t *cpu, arm_exception ex)
{
    return cpu->exceptions[ex].priority;
}

void cpu_set_exception_priority(cpu_t *cpu, arm_exception ex, int16_t priority)
{
    if (cpu->exceptions[ex].fixed_priority)
        fault_take(FAULT_CPU_FIXED_EXCEPTION);

    cpu->exceptions[ex].priority = priority;
    cpu->execution_priority = calculate_execution_priority(cpu);
}

bool cpu_is_sleeping(cpu_t *cpu)
{
    return cpu->sleep_fuel > 0;
}

void cpu_set_memory_watchpoint(cpu_t *cpu, uint32_t addr, bool read, bool write, mem_watchpoint_cb_t cb, void *userdata)
{
    cpu->memory_watchpoint.address = addr;
    cpu->memory_watchpoint.read = read;
    cpu->memory_watchpoint.write = write;
    cpu->memory_watchpoint.cb = cb;
    cpu->memory_watchpoint.userdata = userdata;
}

void cpu_clear_memory_watchpoint(cpu_t *cpu)
{
    cpu->memory_watchpoint.read = false;
    cpu->memory_watchpoint.write = false;
}

void cpu_clear_instruction_cache(cpu_t *cpu)
{
    memset(cpu->inst_by_pc, 0, (cpu->program_size / 2) * sizeof(cs_insn *));
}
