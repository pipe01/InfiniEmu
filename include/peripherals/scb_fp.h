#include "peripherals/peripheral.h"

#include "arm.h"

PERIPHERAL(SCB_FP, scb_fp)

FPCCR_t scb_fp_get_fpccr(SCB_FP_t *scb_fp);
uint32_t scb_fp_get_fpscr(SCB_FP_t *scb_fp);
void scb_fp_set_fpscr(SCB_FP_t *scb_fp, uint32_t value);
