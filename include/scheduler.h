#pragma once

#include <stddef.h>
#include <stdint.h>

typedef void (*scheduler_cb_t)(void *userdata);

typedef struct scheduler_t scheduler_t;

scheduler_t *scheduler_new(scheduler_cb_t cb, void *userdata, size_t target_hz);
void scheduler_run(scheduler_t *);
void scheduler_stop(scheduler_t *);
uint64_t scheduler_get_counter(scheduler_t *);
void scheduler_set_frequency(scheduler_t *, size_t target_hz);
