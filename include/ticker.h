#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct ticker_t ticker_t;

typedef enum
{
    CLOCK_HFCLK,
    CLOCK_LFCLK,
} clock_type;

typedef void (*ticker_cb_t)(void *);

ticker_t *ticker_new(int32_t lfclk_cycles);
void ticker_free(ticker_t *);
void ticker_reset(ticker_t *);

void ticker_hftick(ticker_t *, unsigned int count);
void ticker_lftick(ticker_t *);

void ticker_add(ticker_t *, clock_type clock, ticker_cb_t cb, void *userdata, uint32_t interval, bool auto_reload);
void ticker_remove(ticker_t *, clock_type clock, ticker_cb_t cb);
