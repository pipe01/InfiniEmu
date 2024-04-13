#include "peripherals/scb_fp.h"

#include <stdlib.h>
#include <string.h>

#include "byte_util.h"

struct SCB_FP_inst_t
{
    uint32_t fpccr;
};

OPERATION(scb_fp)
{
    SCB_FP_t *scb_fp = (SCB_FP_t *)userdata;

    switch (offset)
    {
    case 0x34: // FPCCR
        OP_RETURN_REG(scb_fp->fpccr, WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

SCB_FP_t *scb_fp_new()
{
    return (SCB_FP_t *)malloc(sizeof(SCB_FP_t));
}

void scb_fp_reset(SCB_FP_t *scb_fp)
{
    memset(scb_fp, 0, sizeof(SCB_FP_t));
}
