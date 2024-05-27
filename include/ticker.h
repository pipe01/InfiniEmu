#pragma once

#include <stdint.h>

typedef struct ticker_t ticker_t;

typedef void (*ticker_cb_t)(void *);

ticker_t *ticker_new();
void ticker_free(ticker_t *);
void ticker_reset(ticker_t *);
void ticker_tick(ticker_t *);
void ticker_add(ticker_t *, ticker_cb_t cb, void *userdata, uint32_t interval);
void ticker_remove(ticker_t *, ticker_cb_t cb);
