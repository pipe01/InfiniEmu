#include "peripherals/nvic.h"

#include "arm.h"
#include "cpu.h"
#include "memory.h"

#include <stdlib.h>
#include <string.h>

typedef struct
{
    bool enabled;
    uint32_t priority;
} interrupt_t;

#define INTERRUPT_COUNT 512

struct NVIC_inst_t
{
    cpu_t *cpu;
};

OPERATION(nvic)
{
    NVIC_t *nvic = (NVIC_t *)userdata;

    // NVIC_ISER[n]
    if (offset <= 0x40)
    {
        OP_ASSERT_SIZE(op, WORD);

        uint32_t iser_num = offset / 4;

        for (uint32_t i = 0; i < 32; i++)
        {
            arm_exception ex_num = ARM_EXTERNAL_INTERRUPT_NUMBER(i + (32 * iser_num));

            if ((*value & (1 << i)) != 0)
                cpu_exception_set_enabled(nvic->cpu, ex_num, true);
        }

        return MEMREG_RESULT_OK;
    }
    // NVIC_ICER[n]
    else if (offset >= 0x80 && offset <= 0xC0)
    {
        // uint8_t *reg = &((uint8_t *)nvic->interrupt_enabled)[offset - 0x80];

        // switch (op)
        // {
        // case OP_READ_BYTE:
        //     *value = *reg;
        //     return MEMREG_RESULT_OK;

        // case OP_WRITE_BYTE:
        //     *reg &= ~*value;
        //     return MEMREG_RESULT_OK;

        // default:
        //     return MEMREG_RESULT_INVALID_ACCESS;
        // }
    }
    // NVIC_IPR[n]
    else if (offset >= 0x300 && offset <= 0x4F0)
    {
        uint32_t ipr_num = offset - 0x300;

        switch (op)
        {
        case OP_WRITE_BYTE:
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num), *value);
            break;

        case OP_WRITE_WORD:
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num), *value & 0xFF);
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 1), (*value >> 8) & 0xFF);
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 2), (*value >> 16) & 0xFF);
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 3), (*value >> 24) & 0xFF);
            break;

        case OP_READ_WORD:
            *value = 
                (cpu_get_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num)) & 0xFF) |
                ((cpu_get_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 1)) & 0xFF) << 8) |
                ((cpu_get_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 2)) & 0xFF) << 16) |
                ((cpu_get_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 3)) & 0xFF) << 24);
            break;

        default:
            return MEMREG_RESULT_INVALID_SIZE;
        }

        return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

NVIC_t *nvic_new(cpu_t *cpu)
{
    NVIC_t *nvic = (NVIC_t *)malloc(sizeof(NVIC_t));
    nvic->cpu = cpu;

    return nvic;
}

void nvic_reset(NVIC_t *nvic)
{
}
