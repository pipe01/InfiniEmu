#include "peripherals/peripheral.h"

NRF52_PERIPHERAL(GPIOTE, gpiote)

void gpiote_step(GPIOTE_t *);
