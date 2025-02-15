#include "pinetime.h"

#define LIB_NAME display
#define DATA_TYPE st7789_t
#include "lualibs/lualibs.h"

#include "lualibs/lua_image.h"

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

DEF_FN(capture)
{
    st7789_t *st = lua_getdata_p(L, 1);

    uint8_t screen_buffer[PINETIME_LCD_WIDTH * PINETIME_LCD_HEIGHT * BYTES_PER_PIXEL];
    st7789_read_screen(st, screen_buffer, PINETIME_LCD_WIDTH, PINETIME_LCD_HEIGHT);

    lua_pushcclosure(L, l_image_new, 0);
    lua_pushinteger(L, PINETIME_LCD_WIDTH);
    lua_pushinteger(L, PINETIME_LCD_HEIGHT);
    lua_pushlightuserdata(L, screen_buffer);
    lua_call(L, 3, 1);

    return 1;
}

DEF_FUNCS{
    END_FN,
};

DEF_METHODS{
    FN(capture),
    END_FN,
};

DEF_LIB(display)
