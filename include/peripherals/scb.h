#pragma once

#include <assert.h>

#include "peripherals/peripheral.h"
#include "cpu.h"

typedef union
{
    struct
    {
        unsigned int NONBASETHRDENA : 1;
        unsigned int USERSETMPEND : 1;
        unsigned int : 1;
        unsigned int UNALIGN_TRP : 1;
        unsigned int DIV_0_TRP : 1;
        unsigned int : 3;
        unsigned int BFHFNMIGN : 3;
        unsigned int STKALIGN : 3;
        unsigned int : 6;
        unsigned int DC : 1;
        unsigned int IC : 1;
        unsigned int BP : 1;
    };
    uint32_t value;
} SCB_CCR_t;

static_assert(sizeof(SCB_CCR_t) == 4, "SCB_CCR_t size is incorrect");

PERIPHERAL(SCB, scb, cpu_t *cpu)

uint32_t scb_get_prigroup(SCB_t *);
SCB_CCR_t scb_get_ccr(SCB_t *);
uint32_t scb_get_cpacr(SCB_t *);
uint32_t scb_get_vtor_tbloff(SCB_t *);
