#pragma once

#include <assert.h>
#include "capstone_inc.h"

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

// TODO: Move this to nrf52832.h
#define ARM_SRAM_START 0x20000000
#define ARM_SRAM_END 0x20010000

typedef union
{
    struct
    {
        unsigned int ipsr : 9;
        unsigned int : 1;
        unsigned int epsr_iciit_l : 6;
        unsigned int apsr_ge0 : 1;
        unsigned int apsr_ge1 : 1;
        unsigned int apsr_ge2 : 1;
        unsigned int apsr_ge3 : 1;
        unsigned int : 4;
        unsigned int epsr_t : 1;
        unsigned int epsr_iciit_h : 2;
        unsigned int apsr_q : 1;
        unsigned int apsr_v : 1;
        unsigned int apsr_c : 1;
        unsigned int apsr_z : 1;
        unsigned int apsr_n : 1;
    };
    uint32_t value;
} xPSR_t;

static_assert(sizeof(xPSR_t) == 4, "xPSR register size has invalid size");

#define xPSR_IT(xpsr) ((xpsr).epsr_iciit_l | ((xpsr).epsr_iciit_h) << 6)

typedef union
{
    struct
    {
        unsigned int nPRIV : 1;
        unsigned int SPSEL : 1;
        unsigned int FPCA : 1;
    };
    uint32_t value;
} CONTROL_t;

static_assert(sizeof(CONTROL_t) == 4, "CONTROL register size has invalid size");

typedef union
{
    struct
    {
        unsigned int LSPACT : 1;
        unsigned int USER : 1;
        unsigned int : 1;
        unsigned int THREAD : 1;
        unsigned int HFRDY : 1;
        unsigned int MMRDY : 1;
        unsigned int BFRDY : 1;
        unsigned int : 1;
        unsigned int MONRDY : 1;
        unsigned int : 21;
        unsigned int LSPEN : 1;
        unsigned int ASPEN : 1;
    };
    uint32_t value;
} FPCCR_t;

static_assert(sizeof(FPCCR_t) == 4, "FPCCR register size has invalid size");

typedef enum
{
    ARM_MODE_THREAD = 0,
    ARM_MODE_HANDLER = 1,
} arm_mode;

typedef enum
{
    ARM_EXC_NONE = 0,

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
    ARM_EXC_EXTERNAL_END = 512
} arm_exception;

#define ARM_EXC_EXTERNAL(n) (ARM_EXC_EXTERNAL_START + (n))

static inline arm_cc invert_cc(arm_cc cc)
{
    switch (cc)
    {
    case ARM_CC_EQ:
        return ARM_CC_NE;
    case ARM_CC_NE:
        return ARM_CC_EQ;
    case ARM_CC_HS:
        return ARM_CC_LO;
    case ARM_CC_LO:
        return ARM_CC_HS;
    case ARM_CC_MI:
        return ARM_CC_PL;
    case ARM_CC_PL:
        return ARM_CC_MI;
    case ARM_CC_VS:
        return ARM_CC_VC;
    case ARM_CC_VC:
        return ARM_CC_VS;
    case ARM_CC_HI:
        return ARM_CC_LS;
    case ARM_CC_LS:
        return ARM_CC_HI;
    case ARM_CC_GE:
        return ARM_CC_LT;
    case ARM_CC_LT:
        return ARM_CC_GE;
    case ARM_CC_GT:
        return ARM_CC_LE;
    case ARM_CC_LE:
        return ARM_CC_GT;
    default:
        return ARM_CC_INVALID;
    }
}
