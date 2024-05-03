#include "peripherals/scb.h"

#include <stdlib.h>

#include "byte_util.h"
#include "cpu.h"
#include "memory.h"

struct SCB_inst_t
{
    uint32_t cpacr;
    uint32_t prigroup;
    uint32_t scr;
    SCB_CCR_t ccr;

    uint32_t fpccr;

    cpu_t *cpu;
};

OPERATION(scb)
{
    SCB_t *scb = (SCB_t *)userdata;

    if (op == OP_RESET)
    {
        scb->cpacr = 0;
        scb->prigroup = 0;
        scb->scr = 0;
        scb->fpccr = 0;
        scb->ccr.value = 0;
        scb->ccr.STKALIGN = 1;
        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
    case 0x04: // ICSR
        OP_ASSERT_SIZE(op, WORD);

        if (OP_IS_READ(op))
        {
            abort(); // TODO: Implement
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

    case 0x0C: // AIRCR
        OP_ASSERT_SIZE(op, WORD);

        if (OP_IS_READ(op))
        {
            *value = 0xFA050000;

            abort(); // TODO: Implement
        }
        else if (OP_IS_WRITE(op))
        {
            if ((*value & x(FFFF, 0000)) != x(05FA, 0000))
                return MEMREG_RESULT_INVALID_ACCESS;

            abort(); // TODO: Implement
        }

        break;

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

SCB_t *scb_new(cpu_t *cpu)
{
    SCB_t *scb = (SCB_t *)malloc(sizeof(SCB_t));
    scb->cpu = cpu;

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
