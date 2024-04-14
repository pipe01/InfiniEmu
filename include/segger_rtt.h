#pragma once

#include "memory.h"

typedef struct rtt_inst_t rtt_t;

rtt_t *rtt_new(memreg_t *mem);
void rtt_free(rtt_t *rtt);
bool rtt_find_control(rtt_t *rtt);
void rtt_flush_buffers(rtt_t *rtt);
