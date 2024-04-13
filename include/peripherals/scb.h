#pragma once

#include "peripherals/peripheral.h"

PERIPHERAL(SCB, scb)

struct SCB_inst_t
{
    uint32_t cpacr;
    uint32_t prigroup;
};
