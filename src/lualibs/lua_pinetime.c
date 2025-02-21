#include "pinetime.h"

#define LIB_NAME pinetime
#define DATA_TYPE pinetime_t
#include "lualibs/lualibs.h"
#include "lualibs/lua_display.h"
#include "lualibs/lua_touch.h"

#include <string.h>

DEF_FN(new)
{
    if (!lua_istable(L, 1))
        luaL_error(L, "Invalid argument: expected table");

    lua_pushstring(L, "firmware");
    lua_gettable(L, 1);

    if (lua_isnil(L, -1))
        luaL_error(L, "Invalid argument: expected 'firmware'");

    const char *firmware_path = luaL_checkstring(L, -1);

    size_t flash_size = NRF52832_FLASH_SIZE;

    lua_pushstring(L, "flash_size");
    lua_gettable(L, 1);
    if (!lua_isnil(L, -1))
        flash_size = luaL_checkinteger(L, -1);

    program_t *program = program_new(flash_size);

    size_t firmware_size = 0;
    uint8_t *firmware = read_file_u8(firmware_path, &firmware_size);
    if (firmware == NULL)
        luaL_error(L, "Failed to read firmware: %s", firmware_path);

    program_load(program, 0, firmware, firmware_size);

    pinetime_t **pt = lua_newuserdata(L, sizeof(pinetime_t **));

    luaL_getmetatable(L, METATABLE);
    lua_setmetatable(L, -2);

    *pt = pinetime_new(program);

    pinetime_reset(*pt);

    return 1;
}

DEF_FN(run)
{
    pinetime_t *pt = lua_getdata_p(L, 1);

    int cycles = 0;

    if (lua_isnumber(L, 2))
    {
        cycles = NRF52832_HFCLK_FREQUENCY * luaL_checknumber(L, 2);
    }
    else if (lua_istable(L, 2))
    {
        lua_pushstring(L, "seconds");
        lua_gettable(L, 2);
        if (!lua_isnil(L, -1))
        {
            cycles = NRF52832_HFCLK_FREQUENCY * luaL_checknumber(L, -1);
        }
        else
        {
            lua_pushstring(L, "cycles");
            lua_gettable(L, 2);

            if (lua_isnil(L, -1))
                luaL_error(L, "Invalid argument: expected 'seconds' or 'cycles'");

            cycles = luaL_checkinteger(L, -1);
        }
    }
    else
    {
        luaL_error(L, "Invalid argument: expected number or table");
    }

    int rem_cycles = cycles;

    while (rem_cycles > 0)
    {
        rem_cycles -= pinetime_step(pt);
    }

    lua_pushinteger(L, cycles - rem_cycles);
    return 1;
}

DEF_FN(reset)
{
    pinetime_t *pt = lua_getdata_p(L, 1);

    pinetime_reset(pt);

    return 0;
}

DEF_FN(__index)
{
    pinetime_t *pt = lua_getdata_p(L, 1);

    luaL_argcheck(L, lua_isstring(L, 2), 2, "Expected string");

    const char *key = lua_tostring(L, 2);

    if (strcmp(key, "display") == 0)
    {
        lua_pushcclosure(L, l_display_new, 0);
        lua_pushlightuserdata(L, pinetime_get_st7789(pt));
        lua_call(L, 1, 1);
        return 1;
    }
    if (strcmp(key, "touch") == 0)
    {
        lua_pushcclosure(L, l_touch_new, 0);
        lua_pushlightuserdata(L, pinetime_get_cst816s(pt));
        lua_call(L, 1, 1);
        return 1;
    }

    // Delegate to metatable
    lua_getmetatable(L, 1);
    lua_pushvalue(L, 2);
    lua_gettable(L, -2);

    return 1;
}

DEF_FN(__gc)
{
    pinetime_t *pt = lua_getdata_p(L, 1);

    pinetime_free(pt);

    return 0;
}

DEF_FUNCS{
    FN(new),
    END_FN,
};

DEF_METHODS{
    FN(run),
    FN(reset),
    FN(__index),
    FN(__gc),
    END_FN,
};

DEF_LIB(pinetime)
