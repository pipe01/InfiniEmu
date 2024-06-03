#include "pinetime.h"

bool pinetime_loop(pinetime_t *pt, size_t n)
{
    st7789_t *lcd = pinetime_get_st7789(pt);
    size_t initial_write_count = st7789_get_write_count(lcd);
    bool updated = false;

    while (n--)
    {
        pinetime_step(pt);

        if (!updated && st7789_get_write_count(lcd) != initial_write_count)
            updated = true;
    }

    return updated;
}
