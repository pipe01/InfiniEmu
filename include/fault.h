#pragma once

#include <setjmp.h>

typedef enum
{
    FAULT_UNKNOWN = 1,

    FAULT_MEMORY_INVALID_ACCESS,
    FAULT_MEMORY_INVALID_SIZE,
    FAULT_MEMORY_UNHANDLED,

    FAULT_CPU_INVALID_INSTRUCTION,
    FAULT_CPU_PC_ALIGNMENT,
    FAULT_CPU_FP_DISABLED,

    FAULT_I2C_UNKNOWN_COMMAND,
} fault_type_t;

void fault_set_jmp(jmp_buf *buf);
void fault_clear_jmp();
void fault_take(fault_type_t t) __THROW __attribute__((__noreturn__));
