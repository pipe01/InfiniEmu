#include "peripherals/nvic.h"

#include "arm.h"
#include "byte_util.h"
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
    uint32_t priority_mask;
};

uint32_t get_pending_value(NVIC_t *nvic, uint32_t reg_index)
{
    uint32_t value = 0;

    for (size_t i = 0; i < 32; i++)
    {
        if (cpu_exception_is_pending(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(i + (32 * reg_index))))
            value |= 1 << i;
    }

    return value;
}

OPERATION(nvic)
{
    NVIC_t *nvic = (NVIC_t *)userdata;

    if (op == OP_RESET)
    {
        // TODO: Implement
        return MEMREG_RESULT_OK;
    }

    // NVIC_ISER[n] and NVIC_ICER[n]
    if (offset <= 0x40 || (offset >= 0x80 && offset <= 0xBC))
    {
        OP_ASSERT_SIZE(op, WORD);

        bool is_set = offset <= 0x40;
        uint32_t iser_num = offset / 4;

        if (OP_IS_READ(op))
            *value = 0;

        for (uint32_t i = 0; i < 32; i++)
        {
            arm_exception ex_num = ARM_EXTERNAL_INTERRUPT_NUMBER(i + (32 * iser_num));

            if (OP_IS_WRITE(op))
            {
                if ((*value & (1 << i)) != 0)
                    cpu_exception_set_enabled(nvic->cpu, ex_num, is_set);
            }
            else if (cpu_exception_get_enabled(nvic->cpu, ex_num))
            {
                *value |= 1 << i;
            }
        }

        return MEMREG_RESULT_OK;
    }
    // NVIC_ISPR[n]
    else if (offset >= 0x100 && offset <= 0x13C + 4)
    {
        OP_ASSERT_SIZE(op, WORD);

        uint32_t reg_index = (offset - 0x100) / 4;

        if (OP_IS_READ(op))
        {
            *value = get_pending_value(nvic, reg_index);
        }
        else
        {
            for (size_t i = 0; i < 32; i++)
            {
                if ((*value & (1 << i)) != 0)
                    cpu_exception_set_pending(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(32 * reg_index + i));
            }
        }

        return MEMREG_RESULT_OK;
    }
    // NVIC_ICPR[n]
    else if (offset >= 0x180 && offset <= 0x1BC + 4)
    {
        OP_ASSERT_SIZE(op, WORD);

        uint32_t reg_index = (offset - 0x180) / 4;

        if (OP_IS_READ(op))
        {
            *value = get_pending_value(nvic, reg_index);
        }
        else
        {
            for (size_t i = 0; i < 32; i++)
            {
                if ((*value & (1 << i)) != 0)
                    cpu_exception_clear_pending(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(32 * reg_index + i));
            }
        }

        return MEMREG_RESULT_OK;
    }
    // NVIC_IPR[n]
    else if (offset >= 0x300 && offset <= 0x4F0)
    {
        uint32_t ipr_num = offset - 0x300;
        Register4 *reg4 = (Register4 *)value;

        switch (op)
        {
        case OP_WRITE_BYTE:
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num), *value & nvic->priority_mask);
            break;

        case OP_READ_BYTE:
            *value = cpu_get_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num));
            break;

        case OP_WRITE_WORD:
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num), reg4->a & nvic->priority_mask);
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 1), reg4->b & nvic->priority_mask);
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 2), reg4->c & nvic->priority_mask);
            cpu_set_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 3), reg4->d & nvic->priority_mask);
            break;

        case OP_READ_WORD:
            reg4->a = cpu_get_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num)) & 0xFF;
            reg4->b = cpu_get_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 1)) & 0xFF;
            reg4->c = cpu_get_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 2)) & 0xFF;
            reg4->d = cpu_get_exception_priority(nvic->cpu, ARM_EXTERNAL_INTERRUPT_NUMBER(ipr_num + 3)) & 0xFF;
            break;

        default:
            return MEMREG_RESULT_INVALID_SIZE;
        }

        return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

NVIC_t *nvic_new(cpu_t *cpu, size_t priority_bits)
{
    assert(priority_bits >= 3 && priority_bits <= 8);

    NVIC_t *nvic = (NVIC_t *)malloc(sizeof(NVIC_t));
    nvic->cpu = cpu;
    nvic->priority_mask = (0xFF << (8 - priority_bits)) & 0xFF;

    return nvic;
}
