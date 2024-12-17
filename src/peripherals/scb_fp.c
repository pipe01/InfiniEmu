#include "peripherals/scb_fp.h"

#include "arm.h"

#include <stdlib.h>
#include <string.h>

#include "byte_util.h"

struct SCB_FP_inst_t
{
    FPCCR_t fpccr;
    uint32_t fpscr;
};

OPERATION(scb_fp)
{
    SCB_FP_t *scb_fp = userdata;

    if (op == OP_RESET)
    {
        scb_fp->fpccr.ASPEN = 1;
        scb_fp->fpccr.LSPEN = 1;
        scb_fp->fpccr.LSPACT = 0;

        return MEMREG_RESULT_OK;
    }

    switch (offset)
    {
    case 0x34: // FPCCR
        OP_RETURN_REG(scb_fp->fpccr.value, WORD);
    }

    return MEMREG_RESULT_UNHANDLED;
}

SCB_FP_t *scb_fp_new(state_store_t *store)
{
    SCB_FP_t *scb_fp = malloc(sizeof(SCB_FP_t));

    state_store_register(store, STATE_KEY_SCB_FP, scb_fp, sizeof(SCB_FP_t));

    return scb_fp;
}

FPCCR_t scb_fp_get_fpccr(SCB_FP_t *scb_fp)
{
    return scb_fp->fpccr;
}

uint32_t scb_fp_get_fpscr(SCB_FP_t *scb_fp)
{
    return scb_fp->fpscr;
}

void scb_fp_set_fpscr(SCB_FP_t *scb_fp, uint32_t value)
{
    scb_fp->fpscr = value;
}
