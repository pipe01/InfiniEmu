#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct
{
    uint8_t r, g, b;
} pixel_t;

typedef struct
{
    size_t width, height;
    pixel_t *pixels;
} image_t;

#define LIB_NAME image
#define DATA_TYPE image_t
#include "lualibs/lualibs.h"

#include <png.h>

DEF_FN_PUBLIC(image_new)
{
    size_t width = luaL_checkinteger(L, 1);
    size_t height = luaL_checkinteger(L, 2);
    bool has_data = lua_gettop(L) == 3;

    image_t *image = lua_newuserdata(L, sizeof(image_t));
    luaL_getmetatable(L, METATABLE);
    lua_setmetatable(L, -2);

    image->width = width;
    image->height = height;
    image->pixels = malloc(width * height * sizeof(pixel_t));

    if (has_data)
    {
        if (!lua_isuserdata(L, 3))
            luaL_error(L, "Invalid argument: expected userdata");

        uint8_t *src = lua_touserdata(L, 3);

        for (size_t y = 0; y < height; y++)
        {
            for (size_t x = 0; x < width; x++)
            {
                size_t pixelIndex = (y * width + x) * 2;
                uint16_t pixel16 = (src[pixelIndex] << 8) | src[pixelIndex + 1];

                uint8_t r = (pixel16 >> 11) & 0x1f;
                uint8_t g = (pixel16 >> 5) & 0x3f;
                uint8_t b = pixel16 & 0x1f;

                image->pixels[y * width + x] = (pixel_t){
                    (r * 527 + 23) >> 6,
                    (g * 259 + 33) >> 6,
                    (b * 527 + 23) >> 6,
                };
            }
        }
    }

    return 1;
}

DEF_FN(save)
{
    image_t *image = lua_getdata(L, 1);
    
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
        image->width, image->height,
        8,
        PNG_COLOR_TYPE_RGB,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png, info);

    for (size_t y = 0; y < image->height; y++)
    {
        png_write_row(png, (png_bytep)&image->pixels[y * image->width]);
    }

    png_write_end(png, NULL);

    fclose(fp);

    png_destroy_write_struct(&png, &info);

    return 0;
}

DEF_FN(equal)
{
    image_t *image1 = lua_getdata(L, 1);
    image_t *image2 = lua_getdata(L, 2);

    if (image1->width != image2->width || image1->height != image2->height)
    {
        lua_pushboolean(L, false);
        return 1;
    }

    lua_pushboolean(L, memcmp(image1->pixels, image2->pixels, image1->width * image1->height * sizeof(pixel_t)) == 0);
    return 1;
}

DEF_FUNCS{
    END_FN,
};

DEF_METHODS{
    FN2(__eq, equal),
    FN(save),
    END_FN,
};

DEF_LIB(image)
