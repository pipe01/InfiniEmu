#include "scheduler.h"

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#define SCHEDULER_HZ 50

struct scheduler_t
{
    scheduler_cb_t cb;
    void *userdata;

    uint64_t counter;
};

scheduler_t *scheduler_new(scheduler_cb_t cb, void *userdata)
{
    scheduler_t *scheduler = malloc(sizeof(scheduler_t));
    scheduler->cb = cb;
    scheduler->userdata = userdata;

    return scheduler;
}

void scheduler_run(scheduler_t *sched, size_t target_hz)
{
    struct timeval tv;
    struct timespec ts_rem, ts_req = {0};

    size_t iteration_count = target_hz / SCHEDULER_HZ;
    size_t should_take_ns = (1e9 * iteration_count) / target_hz;

    for (;;)
    {
        gettimeofday(&tv, NULL);
        size_t start = tv.tv_sec * 1e6 + tv.tv_usec;

        for (size_t i = 0; i < iteration_count; i++)
        {
            sched->cb(sched->userdata);
        }
        sched->counter += iteration_count;

        gettimeofday(&tv, NULL);
        size_t end = tv.tv_sec * 1e6 + tv.tv_usec;
        size_t elapsed_ns = (end - start) * 1e3;


        if (elapsed_ns < should_take_ns)
        {
            ts_req.tv_nsec = should_take_ns - elapsed_ns;
            nanosleep(&ts_req, &ts_rem);
        }
    }
}

uint64_t scheduler_get_counter(scheduler_t *sched)
{
    return sched->counter;
}
