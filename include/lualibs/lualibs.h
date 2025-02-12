#pragma once

#include "util.h"

#include <lua/lua.h>
#include <lua/lauxlib.h>
#include <lua/lualib.h>

#ifdef LIB_NAME

#define METATABLE macro_string(LIB_NAME)

#define DEF_FN(name) static int l_##name(lua_State *L)

#define REG_FN(name)                \
    lua_pushcfunction(L, l_##name); \
    lua_setglobal(L, #name);

#define DEF_FUNCS static const luaL_Reg functions[] =
#define DEF_METHODS static const luaL_Reg methods[] =

#define FN2(name, fn) {#name, l_##fn}
#define FN(name) {#name, l_##name}
#define END_FN {NULL, NULL}

#define DEF_LIB(name)                             \
    int luaopen_##name(lua_State *L)              \
    {                                             \
        luaL_newmetatable(L, METATABLE);          \
        lua_pushstring(L, "__index");             \
        lua_pushvalue(L, -2);                     \
        lua_settable(L, -3);                      \
        luaL_setfuncs(L, methods, 0);             \
        lua_newtable(L);                          \
        luaL_setfuncs(L, functions, 0);           \
        lua_setglobal(L, macro_string(LIB_NAME)); \
        return 1;                                 \
    }

#else

#include "lua_pinetime.h"

#endif