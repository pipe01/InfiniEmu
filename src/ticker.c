#include "ticker.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

#define MAX_ENTRIES 10

typedef struct
{
    ticker_cb_t cb;
    void *userdata;
    uint32_t interval, counter;
} ticker_entry_t;

struct ticker_t
{
    ticker_entry_t entries[MAX_ENTRIES];
    size_t count;
};

ticker_t *ticker_new()
{
    return malloc(sizeof(ticker_t));
}

void ticker_free(ticker_t *ticker)
{
    free(ticker);
}

void ticker_reset(ticker_t *ticker)
{
    memset(ticker, 0, sizeof(ticker_t));
}

void ticker_add(ticker_t *ticker, ticker_cb_t cb, void *userdata, uint32_t interval)
{
    assert(ticker->count < MAX_ENTRIES);

    ticker_entry_t *entry = &ticker->entries[ticker->count++];

    entry->cb = cb;
    entry->userdata = userdata;
    entry->interval = interval;
    entry->counter = interval;
}

void ticker_remove(ticker_t *ticker, ticker_cb_t cb)
{
    for (size_t i = 0; i < ticker->count; i++)
    {
        if (ticker->entries[i].cb == cb)
        {
            if (ticker->count == 1)
            {
                ticker->count = 0;
                return;
            }

            // Move last entry to the removed entry
            memcpy(&ticker->entries[i], &ticker->entries[ticker->count - 1], sizeof(ticker_entry_t));
            ticker->count--;
            break;
        }
    }
}

void ticker_tick(ticker_t *ticker)
{
    for (size_t i = 0; i < ticker->count; i++)
    {
        ticker_entry_t *entry = &ticker->entries[i];

        if (--entry->counter == 0)
        {
            entry->counter = entry->interval;
            entry->cb(entry->userdata);
        }
    }
}
