#pragma once

#include <setjmp.h>

typedef enum
{
    FAULT_MEMORY_INVALID_ACCESS = 1,
    FAULT_MEMORY_INVALID_SIZE,
    FAULT_MEMORY_UNHANDLED,

    FAULT_CPU_INVALID_INSTRUCTION,
    FAULT_CPU_PC_ALIGNMENT,
    FAULT_CPU_FP_DISABLED,
} fault_type_t;

void fault_set_jmp(jmp_buf *buf);
void fault_clear_jmp();
void fault_take(fault_type_t t) __THROW __attribute__ ((__noreturn__));
