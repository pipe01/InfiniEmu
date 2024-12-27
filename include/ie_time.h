#pragma once

#include <stdint.h>

#ifdef __EMSCRIPTEN__

#include <emscripten.h>

static inline uint64_t microseconds_now()
{
    return EM_ASM_INT(return performance.now() * 1e3);
}

#else

#include <stddef.h>

uint64_t microseconds_now_real();

#endif
