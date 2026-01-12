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

    rtt_t *rtt;
    bool found_rtt;

    bool stop;

    size_t cycles_per_iteration;
};

scheduler_t *scheduler_new(scheduler_cb_t cb, void *userdata, size_t target_hz, rtt_t *rtt)
{
    scheduler_t *scheduler = malloc(sizeof(scheduler_t));
    scheduler->cb = cb;
    scheduler->userdata = userdata;
    scheduler->rtt = rtt;
    scheduler->stop = false;
    
    scheduler_set_frequency(scheduler, target_hz);

    return scheduler;
}

void scheduler_run(scheduler_t *sched)
{
    struct timespec ts_req = {0};

    sched->stop = false;

    ssize_t fuel, rtt_fuel = 5000, rtt_find_fuel = 20000000;

    while (!sched->stop)
    {
        fuel = sched->cycles_per_iteration;

        uint64_t start = microseconds_now_real();

        while (fuel > 0)
        {
            fuel -= sched->cb(sched->userdata);
        }

        if (sched->rtt)
        {
            if (!sched->found_rtt && rtt_find_fuel > 0)
            {
                sched->found_rtt = rtt_find_control(sched->rtt);
            }

            rtt_fuel -= sched->cycles_per_iteration;
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
