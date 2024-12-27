#include "ie_time.h"

#include <sys/time.h>

static _Thread_local struct timeval tv;

uint64_t microseconds_now_real()
{
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1e6 + tv.tv_usec;
}
