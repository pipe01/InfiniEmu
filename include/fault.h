#pragma once

#include <setjmp.h>
#include <stdio.h>

typedef enum
{
    FAULT_UNKNOWN = 1,

    FAULT_NOT_IMPLEMENTED,

    FAULT_MEMORY_INVALID_ACCESS,
    FAULT_MEMORY_INVALID_SIZE,
    FAULT_MEMORY_UNHANDLED,

    FAULT_CPU_INVALID_INSTRUCTION,
    FAULT_CPU_INVALID_CC,
    FAULT_CPU_INVALID_EXCEPTION_RETURN,
    FAULT_CPU_INVALID_FP_REGISTER,
    FAULT_CPU_INVALID_SYSREG,
    FAULT_CPU_FIXED_EXCEPTION,
    FAULT_CPU_PC_ALIGNMENT,
    FAULT_CPU_FP_DISABLED,
    FAULT_CPU_DIVIDE_BY_ZERO,

    FAULT_DMA_INVALID_ADDRESS,

    FAULT_SPI_COMMAND_TOO_LONG,
    FAULT_SPI_UNKNOWN_COMMAND,

    FAULT_I2C_DUPLICATE_ADDRESS,
    FAULT_I2C_UNKNOWN_ADDRESS,
    FAULT_I2C_UNKNOWN_COMMAND,
    FAULT_I2C_INVALID_DATA,

    FAULT_PPI_DUPLICATE_PERIPHERAL,

    FAULT_ST7789_INVALID_COORDS,
} fault_type_t;

#define assert_fault(cond, fault)                                              \
    do                                                                         \
    {                                                                          \
        if (!(cond))                                                           \
        {                                                                      \
            printf(__FILE__ ":%d: Assertion `" #cond "` failed.\n", __LINE__); \
            fault_take(fault);                                                 \
        }                                                                      \
    } while (0)

#define fault_take(t)                                         \
    do                                                        \
    {                                                         \
        printf(__FILE__ ":%d: took fault %d\n", __LINE__, t); \
        fault_take_(t);                                       \
    } while (0)

void fault_set_jmp(jmp_buf *buf);
void fault_clear_jmp(void);
void fault_take_(fault_type_t t) __attribute__((__nothrow__, __leaf__, __noreturn__));
