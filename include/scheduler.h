#pragma once

#include <stddef.h>
#include <stdint.h>

typedef void (*scheduler_cb_t)(void *userdata);

typedef struct scheduler_t scheduler_t;

scheduler_t *scheduler_new(scheduler_cb_t cb, void *userdata);
void scheduler_run(scheduler_t *, size_t target_hz);
uint64_t scheduler_get_counter(scheduler_t *);
