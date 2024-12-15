#include "scheduler.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "ie_time.h"

#define SCHEDULER_HZ 50

struct scheduler_t
{
    scheduler_cb_t cb;
    void *userdata;

    bool stop;

    size_t iteration_count, should_take_ns;

    uint64_t counter;
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
    struct timespec ts_rem, ts_req = {0};

    sched->stop = false;

    while (!sched->stop)
    {
        // Copy variables here to prevent them from changing during the loop body
        size_t iteration_count = sched->iteration_count;
        size_t should_take_ns = sched->should_take_ns;

        uint64_t start = microseconds_now();

        for (size_t i = 0; i < iteration_count; i++)
        {
            sched->counter += sched->cb(sched->userdata);
        }

        size_t end = microseconds_now();
        size_t elapsed_ns = (end - start) * 1e3;

        if (elapsed_ns < should_take_ns)
        {
            ts_req.tv_nsec = should_take_ns - elapsed_ns;
            nanosleep(&ts_req, &ts_rem);
        }
    }
}

void scheduler_stop(scheduler_t *sched)
{
    sched->stop = true;
}

uint64_t scheduler_get_counter(scheduler_t *sched)
{
    return sched->counter;
}

void scheduler_set_frequency(scheduler_t *sched, size_t target_hz)
{
    sched->iteration_count = target_hz / SCHEDULER_HZ;
    sched->should_take_ns = (1e9 * sched->iteration_count) / target_hz;
}
