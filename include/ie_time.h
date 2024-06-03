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
#include <sys/time.h>

static inline uint64_t microseconds_now()
{
    static _Thread_local struct timeval tv;

    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1e6 + tv.tv_usec;
}

#endif
