#include "peripherals/scb.h"

#include <stdlib.h>

#include "byte_util.h"
#include "cpu.h"
#include "fault.h"
#include "memory.h"

struct SCB_inst_t
{
    struct state
    {
        uint32_t cpacr;
        uint32_t prigroup;
        uint32_t scr;
        SCB_CCR_t ccr;
        uint32_t vtor;
    };

    cpu_t *cpu;
};

OPERATION(scb)
{
    SCB_t *scb = userdata;

    if (op == OP_RESET)
    {
        scb->cpacr = 0;
        scb->prigroup = 0;
        scb->scr = 0;
        scb->ccr.value = 0;
        scb->ccr.STKALIGN = 1;
        scb->vtor = 0;
        return MEMREG_RESULT_OK;
    }

    OP_IGNORE_LOAD_DATA

    switch (offset)
    {
    case 0x00: // CPUID
        OP_ASSERT_READ(op);
        OP_ASSERT_SIZE(op, WORD);

        *value = 0x410FC241; // ARM Cortex-M4
        return MEMREG_RESULT_OK;

    case 0x04: // ICSR
        OP_ASSERT_SIZE(op, WORD);

        if (OP_IS_READ(op))
        {
            *value = 0;

            if (cpu_exception_is_active(scb->cpu, ARM_EXC_NMI))
                *value |= 1 << 31;

            if (cpu_exception_is_pending(scb->cpu, ARM_EXC_PENDSV))
                *value |= 1 << 28;

            if (cpu_exception_is_pending(scb->cpu, ARM_EXC_SYSTICK))
                *value |= 1 << 26;

            // TODO: Set RETTOBASE bit

            arm_exception active_exc = cpu_get_top_running_exception(scb->cpu);
            *value |= active_exc & 0x1FF;
        }
        else
        {
            if (IS_SET(*value, 31)) // NMIPENDSET
                cpu_exception_set_pending(scb->cpu, ARM_EXC_NMI);

            if (IS_SET(*value, 28)) // PENDSVSET
                cpu_exception_set_pending(scb->cpu, ARM_EXC_PENDSV);

            if (IS_SET(*value, 27)) // PENDSVCLR
                cpu_exception_clear_pending(scb->cpu, ARM_EXC_PENDSV);

            if (IS_SET(*value, 26)) // PENDSTSET
                cpu_exception_set_pending(scb->cpu, ARM_EXC_SYSTICK);

            if (IS_SET(*value, 25)) // PENDSTCLR
                cpu_exception_clear_pending(scb->cpu, ARM_EXC_SYSTICK);
        }

        return MEMREG_RESULT_OK;

    case 0x08: // VTOR
        OP_RETURN_REG(scb->vtor, WORD);

    case 0x0C: // AIRCR
        OP_ASSERT_SIZE(op, WORD);

        if (OP_IS_READ(op))
        {
            *value = 0xFA050000 | (scb->prigroup & 0x7) << 8;
        }
        else if (OP_IS_WRITE(op))
        {
            if ((*value & x(FFFF, 0000)) != x(05FA, 0000))
                return MEMREG_RESULT_INVALID_ACCESS;

            scb->prigroup = (*value >> 8) & 0x7;

            if (*value & MASK(2)) // SYSRESETREQ
                cpu_reset(scb->cpu);

            // TODO: Implement other bits
        }

        return MEMREG_RESULT_OK;

    case 0x10: // SCR
        OP_RETURN_REG(scb->scr, WORD);

    case 0x88: // CPACR
        OP_ASSERT_SIZE(op, WORD);

        OP_RETURN_REG(scb->cpacr, WORD);
    }

    // SHPR[n]
    if (offset >= 0x18 && offset <= 0x23)
    {
        OP_ASSERT_SIZE(op, BYTE);

        arm_exception ex = (offset - 0x18) + 4;

        if (OP_IS_READ(op))
            *value = cpu_get_exception_priority(scb->cpu, ex);
        else
            cpu_set_exception_priority(scb->cpu, ex, *value);

        return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

SCB_t *scb_new(cpu_t *cpu, state_store_t *store)
{
    SCB_t *scb = malloc(sizeof(SCB_t));
    scb->cpu = cpu;

    state_store_register(store, STATE_KEY_SCB, scb, sizeof(struct state));

    return scb;
}

uint32_t scb_get_prigroup(SCB_t *scb)
{
    return scb->prigroup;
}

SCB_CCR_t scb_get_ccr(SCB_t *scb)
{
    return scb->ccr;
}

uint32_t scb_get_cpacr(SCB_t *scb)
{
    return scb->cpacr;
}

uint32_t scb_get_vtor_tbloff(SCB_t *scb)
{
    return scb->vtor & 0xFFFFFF80;
}
