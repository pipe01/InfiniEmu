#include "lua.h"
#include "lualibs/lualibs.h"

#include "util.h"

void run_lua(const char *script, size_t script_size, const char *name, pinetime_t *pt)
{
    lua_State *L = luaL_newstate();

    luaL_openselectedlibs(L, LUA_GLIBK | LUA_MATHLIBK | LUA_TABLIBK | LUA_STRLIBK, 0);

    luaopen_display(L);
    luaopen_pinetime(L);
    luaopen_image(L);
    luaopen_touch(L);

    if (luaL_loadbuffer(L, script, script_size, name) || lua_pcall(L, 0, 0, 0))
    {
        fprintf(stderr, "Failed to run Lua script: %s\n", lua_tostring(L, -1));
        lua_close(L);
    }
}

void run_lua_file(const char *script_path, pinetime_t *pt)
{
    size_t script_size;
    uint8_t *script = read_file_u8(script_path, &script_size);

    if (script == NULL)
    {
        fprintf(stderr, "Failed to read Lua script: %s\n", script_path);
        return;
    }

    run_lua((const char *)script, script_size, script_path, pt);

    free(script);
}
