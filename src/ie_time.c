#include "ie_time.h"

#ifdef __EMSCRIPTEN__
extern uint64_t microseconds_now();
#else
#include <stddef.h>
#include <sys/time.h>

_Thread_local struct timeval tv;

uint64_t microseconds_now()
{
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1e6 + tv.tv_usec;
}
#endif
