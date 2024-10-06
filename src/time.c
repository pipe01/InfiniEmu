#include "ie_time.h"

#include <sys/time.h>

static _Thread_local struct timeval tv;

bool use_real_time = true;
uint64_t fake_microseconds = 0;

uint64_t microseconds_now_real()
{
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1e6 + tv.tv_usec;
}

uint64_t microseconds_now()
{
    if (use_real_time)
    {
        return microseconds_now_real();
    }

    return fake_microseconds;
}

void time_use_real_time(bool use)
{
    use_real_time = use;
}

void time_increment_fake_microseconds(uint64_t inc)
{
    fake_microseconds += inc;
}
