#include "pinetime.h"

#define LIB_NAME touch
#define DATA_TYPE cst816s_t
#include "lualibs/lualibs.h"

#include <string.h>

DEF_FN_PUBLIC(touch_new)
{
    if (!lua_isuserdata(L, 1))
        luaL_error(L, "Invalid argument: expected userdata");

    cst816s_t **touch = lua_newuserdata(L, sizeof(cst816s_t **));

    luaL_getmetatable(L, METATABLE);
    lua_setmetatable(L, -2);

    *touch = lua_touserdata(L, 1);

    return 1;
}

DEF_FN(swipe)
{
    cst816s_t *ts = lua_getdata_p(L, 1);

    touch_gesture_t gesture = GESTURE_NONE;

    if (lua_isstring(L, 2))
    {
        const char *gesture_str = lua_tostring(L, 2);

        if (strcmp(gesture_str, "down") == 0)
            gesture = GESTURE_SLIDEDOWN;
        else if (strcmp(gesture_str, "up") == 0)
            gesture = GESTURE_SLIDEUP;
        else if (strcmp(gesture_str, "left") == 0)
            gesture = GESTURE_SLIDELEFT;
        else if (strcmp(gesture_str, "right") == 0)
            gesture = GESTURE_SLIDERIGHT;
        else
            luaL_error(L, "Invalid argument: expected 'down', 'up', 'left' or 'right'");
    }
    else
    {
        luaL_error(L, "Invalid argument: expected string");
    }

    uint32_t x = 0, y = 0;

    if (lua_istable(L, 3))
    {
        lua_pushinteger(L, 1);
        lua_gettable(L, 3);
        x = luaL_checkinteger(L, -1);

        lua_pushinteger(L, 2);
        lua_gettable(L, 3);
        y = luaL_checkinteger(L, -1);
    }

    cst816s_do_touch(ts, gesture, x, y);

    return 0;
}

DEF_FN(tap)
{
    cst816s_t *ts = lua_getdata_p(L, 1);

    uint32_t x = luaL_checkinteger(L, 2);
    uint32_t y = luaL_checkinteger(L, 3);

    cst816s_do_touch(ts, GESTURE_SINGLETAP, x, y);

    return 0;
}

DEF_FN(release)
{
    cst816s_t *ts = lua_getdata_p(L, 1);

    cst816s_release_touch(ts);

    return 0;
}

DEF_FUNCS{
    END_FN,
};

DEF_METHODS{
    FN(swipe),
    FN(tap),
    FN(release),
    END_FN,
};

DEF_LIB(touch)
