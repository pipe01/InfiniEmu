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
    ticker_entry_t lf_entries[MAX_ENTRIES];
    size_t lf_entries_count;
    ticker_entry_t hf_entries[MAX_ENTRIES];
    size_t hf_entries_count;

    uint32_t lfclk_divider, lfclk_counter;
    bool lfclk_enabled;
};

ticker_t *ticker_new(int32_t lfclk_divider)
{
    ticker_t *ticker = calloc(1, sizeof(ticker_t));

    if (lfclk_divider > 0)
    {
        ticker->lfclk_divider = lfclk_divider;
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
    ticker->lf_entries_count = 0;
    ticker->hf_entries_count = 0;
}

#define CLOCK_ENTRIES(clock) (clock == CLOCK_HFCLK ? ticker->hf_entries : ticker->lf_entries)
#define CLOCK_ENTRIES_COUNT(clock) (clock == CLOCK_HFCLK ? &ticker->hf_entries_count : &ticker->lf_entries_count)

void ticker_add(ticker_t *ticker, clock_type clock, ticker_cb_t cb, void *userdata, uint32_t interval, bool auto_reload)
{
    ticker_entry_t *entries = CLOCK_ENTRIES(clock);
    size_t *entries_count = CLOCK_ENTRIES_COUNT(clock);

    assert(*entries_count < MAX_ENTRIES);

    ticker_entry_t *entry = &entries[(*entries_count)++];

    entry->cb = cb;
    entry->userdata = userdata;
    entry->interval = interval;
    entry->counter = 0;
    entry->auto_reload = auto_reload;
}

void ticker_remove(ticker_t *ticker, clock_type clock, ticker_cb_t cb)
{
    ticker_entry_t *entries = CLOCK_ENTRIES(clock);
    size_t *entries_count = CLOCK_ENTRIES_COUNT(clock);

    for (size_t i = 0; i < *entries_count; i++)
    {
        if (entries[i].cb == cb)
        {
            if (*entries_count == 1)
            {
                *entries_count = 0;
                return;
            }

            // Move last entry to the removed entry
            memcpy(&entries[i], &entries[*entries_count - 1], sizeof(ticker_entry_t));

            (*entries_count)--;
            break;
        }
    }
}

static inline void tick_entries(ticker_entry_t *entries, size_t *entries_count)
{
    for (size_t i = 0; i < *entries_count; i++)
    {
        ticker_entry_t *entry = &entries[i];

        if (++entry->counter == entry->interval)
        {
            entry->cb(entry->userdata);

            if (entry->auto_reload)
            {
                entry->counter = 0;
            }
            else
            {
                // Move last entry to the removed entry
                memcpy(entry, &entries[*entries_count - 1], sizeof(ticker_entry_t));

                (*entries_count)--;
                i--;
            }
        }
    }
}

void ticker_hftick(ticker_t *ticker, unsigned int count)
{
    for (size_t i = 0; i < count; i++)
    {
        tick_entries(ticker->hf_entries, &ticker->hf_entries_count);
    }

    if (!ticker->lfclk_enabled)
        return;

    ticker->lfclk_counter += count;

    while (ticker->lfclk_counter >= ticker->lfclk_divider)
    {
        ticker_lftick(ticker);
        ticker->lfclk_counter -= ticker->lfclk_divider;
    }
}

void ticker_lftick(ticker_t *ticker)
{
    tick_entries(ticker->lf_entries, &ticker->lf_entries_count);
}
