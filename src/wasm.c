#include "pinetime.h"

void pinetime_loop(pinetime_t *pt, size_t n)
{
    while (n--)
    {
        pinetime_step(pt);
    }
}

void memset_test(uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        data[i] = 0xA5;
    }
}
