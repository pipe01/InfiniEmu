#include "peripherals/nvic.h"
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
    uint32_t interrupt_enabled[INTERRUPT_COUNT / 32];
    uint32_t interrupt_priority[INTERRUPT_COUNT];
};

OPERATION(nvic)
{
    NVIC_t *nvic = (NVIC_t *)userdata;

    // NVIC_ISER[n]
    if (offset <= 0x40)
    {
        if (OP_IS_SIZE(op, BYTE))
        {
            uint8_t *reg = &((uint8_t *)nvic->interrupt_enabled)[offset];

            if (OP_IS_READ(op))
                *value = *reg;
            else if (OP_IS_WRITE(op))
                *reg |= *value;

            return true;
        }
        else if (OP_IS_SIZE(op, WORD))
        {
            uint32_t *reg = &((uint32_t *)nvic->interrupt_enabled)[offset / 4];

            if (OP_IS_READ(op))
                *value = *reg;
            else if (OP_IS_WRITE(op))
                *reg |= *value;

            return true;
        }
    }
    // NVIC_ICER[n]
    else if (offset >= 0x80 && offset <= 0xC0)
    {
        uint8_t *reg = &((uint8_t *)nvic->interrupt_enabled)[offset - 0x80];

        switch (op)
        {
        case OP_READ_BYTE:
            *value = *reg;
            return true;

        case OP_WRITE_BYTE:
            *reg &= ~*value;
            return true;
        }
    }
    // NVIC_IPR[n]
    else if (offset >= 0x300 && offset <= 0x4F0)
    {
        OP_RETURN_REG(nvic->interrupt_priority[offset - 0x300], BYTE);
    }

    return false;
}

NVIC_t *nvic_new()
{
    return (NVIC_t *)malloc(sizeof(NVIC_t));
}

void nvic_reset(NVIC_t *nvic)
{
    memset(nvic->interrupt_enabled, 0, sizeof(nvic->interrupt_enabled));
}
