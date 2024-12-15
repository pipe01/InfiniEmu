#include "scheduler.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "ie_time.h"

#define US_PER_ITERATION 100000

struct scheduler_t
{
    scheduler_cb_t cb;
    void *userdata;

    bool stop;

    size_t cycles_per_iteration;
};

scheduler_t *scheduler_new(scheduler_cb_t cb, void *userdata, size_t target_hz)
{
    scheduler_t *scheduler = malloc(sizeof(scheduler_t));
    scheduler->cb = cb;
    scheduler->userdata = userdata;
    scheduler->stop = false;
    
    scheduler_set_frequency(scheduler, target_hz);

    return scheduler;
}

void scheduler_run(scheduler_t *sched)
{
    struct timespec ts_req = {0};

    sched->stop = false;

    ssize_t fuel;

    while (!sched->stop)
    {
        fuel = sched->cycles_per_iteration;

        uint64_t start = microseconds_now_real();

        while (fuel > 0)
        {
            fuel -= sched->cb(sched->userdata);
        }

        uint64_t elapsed_us = microseconds_now_real() - start;

        if (elapsed_us < US_PER_ITERATION)
        {
            ts_req.tv_nsec = (US_PER_ITERATION - elapsed_us) * 1000;
            while (nanosleep(&ts_req, &ts_req));
        }
    }
}

void scheduler_stop(scheduler_t *sched)
{
    sched->stop = true;
}

void scheduler_set_frequency(scheduler_t *sched, size_t target_hz)
{
    sched->cycles_per_iteration = (target_hz * US_PER_ITERATION) / 1000000;
}
