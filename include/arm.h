#pragma once

#define APSR_N 31
#define APSR_Z 30
#define APSR_C 29
#define APSR_V 28
#define APSR_Q 27
#define APSR_GE (0b1111 << 16)

#define IPSR_MASK ((1 << 9) - 1)

#define EPSR_T 24

#define CONTROL_nPRIV 0
#define CONTROL_SPSEL 1
#define CONTROL_FPCA 2

#define ARM_MAX_EXCEPTIONS 512
#define ARM_MAX_PRIORITY 255
#define ARM_EXTERNAL_INTERRUPT_NUMBER(n) (16 + (n))

typedef enum
{
    ARM_MODE_THREAD = 0,
    ARM_MODE_HANDLER = 1,
} arm_mode;

typedef enum
{
    ARM_EXC_RESET = 1,
    ARM_EXC_NMI = 2,
    ARM_EXC_HARDFAULT = 3,
    ARM_EXC_MEMMANAGE = 4,
    ARM_EXC_BUSFAULT = 5,
    ARM_EXC_USAGEFAULT = 6,
    ARM_EXC_SVC = 11,
    ARM_EXC_DEBUGMONITOR = 12,
    ARM_EXC_PENDSV = 14,
    ARM_EXC_SYSTICK = 15,

    ARM_EXC_EXTERNAL_START = 16,
    ARM_EXC_EXTERNAL_END = 512,
} arm_exception;

#define ARM_EXC_EXTERNAL(n) (ARM_EXC_EXTERNAL_START + (n))
