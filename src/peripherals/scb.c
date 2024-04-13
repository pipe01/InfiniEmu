#include "peripherals/scb.h"

#include <stdlib.h>

#include "byte_util.h"
#include "cpu.h"
#include "memory.h"

struct SCB_inst_t
{
    uint32_t cpacr;
    uint32_t prigroup;

    cpu_t *cpu;
};

OPERATION(scb)
{
    SCB_t *scb = (SCB_t *)userdata;

    switch (offset)
    {
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

void scb_reset(SCB_t *scb)
{
    scb->cpacr = 0;
}

uint32_t scb_get_prigroup(SCB_t *scb)
{
    return scb->prigroup;
}
