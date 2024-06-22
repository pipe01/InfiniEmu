#include "pinetime.h"
#include "components/spi/st7789.h"

#include <emscripten.h>

bool pinetime_loop(pinetime_t *pt, size_t n)
{
    st7789_t *lcd = pinetime_get_st7789(pt);
    size_t initial_write_count = st7789_get_write_count(lcd);

    while (n--)
    {
        pinetime_step(pt);
    }

    return st7789_get_write_count(lcd) != initial_write_count;
}

void st7789_read_screen_rgba(st7789_t *st, uint8_t *screen_buffer, uint8_t *rgba_buffer, size_t width, size_t height)
{
    st7789_read_screen(st, screen_buffer, width, height);

    size_t pixel_idx = 0;

    for (size_t y = 0; y < height; y++)
    {
        for (size_t x = 0; x < width; x++)
        {
            uint16_t pixel16 = screen_buffer[pixel_idx * BYTES_PER_PIXEL + 1] | (screen_buffer[pixel_idx * BYTES_PER_PIXEL] << 8);

            uint16_t r = (pixel16 >> 11) & 0x1f;
            uint16_t g = (pixel16 >> 5) & 0x3f;
            uint16_t b = pixel16 & 0x1f;

            rgba_buffer[pixel_idx * 4] = (r * 527 + 23) >> 6;
            rgba_buffer[pixel_idx * 4 + 1] = (g * 259 + 33) >> 6;
            rgba_buffer[pixel_idx * 4 + 2] = (b * 527 + 23) >> 6;
            rgba_buffer[pixel_idx * 4 + 3] = 0xFF; // Alpha is always 0xFF

            pixel_idx++;
        }
    }
}

void commander_output(const char *msg, void *userdata)
{
    EM_ASM({
        console.log($0);
    }, msg);
}
