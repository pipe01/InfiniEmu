#define LIB_NAME display
#include "lualibs/lualibs.h"

#include "pinetime.h"

#include <png.h>

DEF_FN_PUBLIC(display_new)
{
    if (!lua_isuserdata(L, 1))
        luaL_error(L, "Invalid argument: expected userdata");

    st7789_t **display = lua_newuserdata(L, sizeof(st7789_t **));

    luaL_getmetatable(L, METATABLE);
    lua_setmetatable(L, -2);

    *display = lua_touserdata(L, 1);

    return 1;
}

DEF_FN(save)
{
    st7789_t **st = luaL_checkudata(L, 1, METATABLE);
    luaL_argcheck(L, *st != NULL, 1, "Invalid display");

    const char *filename = luaL_checkstring(L, 2);

    FILE *fp = fopen(filename, "wb");
    if (!fp)
        abort();

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png)
        abort();

    png_infop info = png_create_info_struct(png);
    if (!info)
        abort();

    if (setjmp(png_jmpbuf(png)))
        abort();

    png_init_io(png, fp);

    png_set_IHDR(
        png,
        info,
        PINETIME_LCD_WIDTH, PINETIME_LCD_HEIGHT,
        8,
        PNG_COLOR_TYPE_RGB,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png, info);

    uint8_t screen_buffer[PINETIME_LCD_WIDTH * PINETIME_LCD_HEIGHT * BYTES_PER_PIXEL];
    st7789_read_screen(*st, screen_buffer, PINETIME_LCD_WIDTH, PINETIME_LCD_HEIGHT);

    png_byte row[PINETIME_LCD_WIDTH * 3];
    for (size_t y = 0; y < PINETIME_LCD_HEIGHT; y++)
    {
        for (size_t x = 0; x < PINETIME_LCD_WIDTH; x++)
        {
            size_t pixelIndex = (y * PINETIME_LCD_WIDTH + x) * 2;
            uint16_t pixel16 = (screen_buffer[pixelIndex] << 8) | screen_buffer[pixelIndex + 1];

            uint8_t r = (pixel16 >> 11) & 0x1f;
            uint8_t g = (pixel16 >> 5) & 0x3f;
            uint8_t b = pixel16 & 0x1f;

            row[x * 3] = (r * 527 + 23) >> 6;
            row[x * 3 + 1] = (g * 259 + 33) >> 6;
            row[x * 3 + 2] = (b * 527 + 23) >> 6;
        }

        png_write_row(png, row);
    }

    png_write_end(png, NULL);

    fclose(fp);

    png_destroy_write_struct(&png, &info);

    return 0;
}

DEF_FUNCS{
    END_FN,
};

DEF_METHODS{
    FN(save),
    END_FN,
};

DEF_LIB(display)
