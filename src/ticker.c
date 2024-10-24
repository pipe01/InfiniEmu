#include "ticker.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES 10

typedef struct
{
    ticker_cb_t cb;
    void *userdata;
    uint32_t interval, counter;
    bool auto_reload;
} ticker_entry_t;

struct ticker_t
{
    ticker_entry_t entries[MAX_ENTRIES];
    size_t entries_count;

    uint32_t lfclk_cycles, lfclk_counter;
    bool lfclk_enabled;
};

ticker_t *ticker_new(int32_t lfclk_cycles)
{
    ticker_t *ticker = calloc(1, sizeof(ticker_t));

    if (lfclk_cycles > 0)
    {
        ticker->lfclk_cycles = lfclk_cycles;
        ticker->lfclk_enabled = true;
    }

    return ticker;
}

void ticker_free(ticker_t *ticker)
{
    free(ticker);
}

void ticker_reset(ticker_t *ticker)
{
    ticker->entries_count = 0;
}

void ticker_add(ticker_t *ticker, ticker_cb_t cb, void *userdata, uint32_t interval, bool auto_reload)
{
    assert(ticker->entries_count < MAX_ENTRIES);

    ticker_entry_t *entry = &ticker->entries[ticker->entries_count++];

    entry->cb = cb;
    entry->userdata = userdata;
    entry->interval = interval;
    entry->counter = 0;
    entry->auto_reload = auto_reload;
}

void ticker_remove(ticker_t *ticker, ticker_cb_t cb)
{
    for (size_t i = 0; i < ticker->entries_count; i++)
    {
        if (ticker->entries[i].cb == cb)
        {
            if (ticker->entries_count == 1)
            {
                ticker->entries_count = 0;
                return;
            }

            // Move last entry to the removed entry
            memcpy(&ticker->entries[i], &ticker->entries[ticker->entries_count - 1], sizeof(ticker_entry_t));

            ticker->entries_count--;
            break;
        }
    }
}

void ticker_hftick(ticker_t *ticker, unsigned int count)
{
    if (!ticker->lfclk_enabled)
        return;

    ticker->lfclk_counter += count;

    if (ticker->lfclk_counter >= ticker->lfclk_cycles)
    {
        ticker_lftick(ticker);
        ticker->lfclk_counter = 0;
    }
}

void ticker_lftick(ticker_t *ticker)
{
    for (size_t i = 0; i < ticker->entries_count; i++)
    {
        ticker_entry_t *entry = &ticker->entries[i];

        if (++entry->counter == entry->interval)
        {
            entry->cb(entry->userdata);

            if (entry->auto_reload)
            {
                entry->counter = 0;
            }
            else
            {
                ticker_remove(ticker, entry->cb);
                i--;
            }
        }
    }
}
