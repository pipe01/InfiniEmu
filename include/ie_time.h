#pragma once

#include <stdint.h>

#ifdef __EMSCRIPTEN__

#include <emscripten.h>

static inline uint64_t microseconds_now()
{
    return EM_ASM_INT(return performance.now() * 1e3);
}

#else

#include <stdbool.h>
#include <stddef.h>

uint64_t microseconds_now();
uint64_t microseconds_now_real();
void time_use_real_time(bool use);
void time_increment_fake_microseconds(uint64_t inc);

#endif
