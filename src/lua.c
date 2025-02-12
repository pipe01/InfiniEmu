#include "lua.h"

#include <lua/lua.h>
#include <lua/lauxlib.h>
#include <lua/lualib.h>

static const char pt_key = 'P';

#define GET_PT                                 \
    lua_pushlightuserdata(L, (void *)&pt_key); \
    lua_gettable(L, LUA_REGISTRYINDEX);        \
    pinetime_t *pt = lua_touserdata(L, -1);

#define DEF_FN(name) static int l_##name(lua_State *L)

#define REG_FN(name)                \
    lua_pushcfunction(L, l_##name); \
    lua_setglobal(L, #name);

DEF_FN(run)
{
    GET_PT;

    int cycles;

    if (lua_isnumber(L, 1))
    {
        cycles = NRF52832_HFCLK_FREQUENCY * luaL_checknumber(L, 1);
    }
    else if (lua_istable(L, 1))
    {
        lua_pushstring(L, "seconds");
        lua_gettable(L, 1);
        if (!lua_isnil(L, -1))
        {
            cycles = NRF52832_HFCLK_FREQUENCY * luaL_checknumber(L, -1);
        }
        else
        {
            lua_pushstring(L, "cycles");
            lua_gettable(L, 1);

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

void run_lua(const char *script, size_t script_size, const char *name, pinetime_t *pt)
{
    lua_State *L = luaL_newstate();

    luaL_openselectedlibs(L, LUA_MATHLIBK | LUA_TABLIBK | LUA_STRLIBK, 0);

    REG_FN(run);

    lua_pushlightuserdata(L, (void *)&pt_key);
    lua_pushlightuserdata(L, pt);
    lua_settable(L, LUA_REGISTRYINDEX);

    if (luaL_loadbuffer(L, script, script_size, name) || lua_pcall(L, 0, 0, 0))
    {
        fprintf(stderr, "Failed to run Lua script: %s\n", lua_tostring(L, -1));
        lua_close(L);
    }
}

void run_lua_file(const char *script_path, pinetime_t *pt)
{
    FILE *script_file = fopen(script_path, "rb");
    if (script_file == NULL)
    {
        fprintf(stderr, "Failed to open Lua script: %s\n", script_path);
        return;
    }

    fseek(script_file, 0, SEEK_END);
    long script_size = ftell(script_file);
    fseek(script_file, 0, SEEK_SET);

    char *script_buffer = malloc(script_size + 1);
    if (script_buffer == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for Lua script\n");
        fclose(script_file);
        return;
    }

    fread(script_buffer, 1, script_size, script_file);
    script_buffer[script_size] = '\0';

    fclose(script_file);

    run_lua(script_buffer, script_size, script_path, pt);

    free(script_buffer);
}
