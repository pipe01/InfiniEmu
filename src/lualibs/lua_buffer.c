#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct buffer_t
{
    uint8_t *data;
    size_t len;
};

#define LIB_NAME buffer
#define DATA_TYPE struct buffer_t
#include "lualibs/lualibs.h"

#include "lualibs/lua_buffer.h"

buffer_t *create_buffer(lua_State *L, size_t len)
{
    buffer_t *buffer = lua_newuserdata(L, sizeof(buffer_t));
    buffer->data = malloc(len);
    buffer->len = len;

    luaL_getmetatable(L, METATABLE);
    lua_setmetatable(L, -2);

    return buffer;
}

uint8_t *buffer_get_data(buffer_t *buffer)
{
    return buffer->data;
}

size_t buffer_get_len(buffer_t *buffer)
{
    return buffer->len;
}

DEF_FN(new)
{
    if (lua_isnumber(L, 1))
    {
        int len = lua_tonumber(L, 1);
        if (len < 0)
        {
            return luaL_error(L, "Invalid argument: expected positive number");
        }

        create_buffer(L, len);
        return 1;
    }

    if (lua_istable(L, 1))
    {
        size_t len = lua_rawlen(L, 1);
        buffer_t *buffer = create_buffer(L, len);

        for (size_t i = 0; i < len; i++)
        {
            lua_pushinteger(L, i + 1);
            lua_gettable(L, 1);

            if (!lua_isnumber(L, -1))
            {
                return luaL_error(L, "Invalid argument: expected table of numbers");
            }

            buffer->data[i] = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }

        return 1;
    }

    return luaL_error(L, "Invalid argument: expected number or table");
}

DEF_FN_PUBLIC(buffer_new_copy)
{
    luaL_argcheck(L, lua_isuserdata(L, 1), 1, "Invalid argument: expected userdata");

    const uint8_t *data = lua_touserdata(L, 1);

    size_t len = lua_tonumber(L, 2);
    if (len <= 0)
    {
        return luaL_error(L, "Invalid argument: expected positive number");
    }

    buffer_t *buffer = create_buffer(L, len);
    memcpy(buffer->data, data, len);

    return 1;
}

DEF_FN(__gc)
{
    buffer_t *buffer = lua_getdata(L, 1);
    free(buffer->data);

    return 0;
}

DEF_FN(__index)
{
    buffer_t *buffer = lua_getdata(L, 1);

    if (!lua_isnumber(L, 2))
    {
        // Delegate to metatable
        lua_getmetatable(L, 1);
        lua_pushvalue(L, 2);
        lua_gettable(L, -2);
        return 1;
    }

    luaL_argcheck(L, lua_isnumber(L, 2), 2, "Expected number");

    int index = lua_tointeger(L, 2);
    if (index < 0 || index >= (int)buffer->len)
    {
        return luaL_error(L, "Index out of bounds: %d", index);
    }

    lua_pushinteger(L, buffer->data[index]);

    return 1;
}

DEF_FN(__newindex)
{
    buffer_t *buffer = lua_getdata(L, 1);

    luaL_argcheck(L, lua_isnumber(L, 2), 2, "Expected number");
    luaL_argcheck(L, lua_isnumber(L, 3), 3, "Expected number");

    int index = lua_tointeger(L, 2);
    if (index < 0 || index >= (int)buffer->len)
    {
        return luaL_error(L, "Index out of bounds: %d", index);
    }

    buffer->data[index] = lua_tointeger(L, 3);

    return 0;
}

DEF_FN(__tostring)
{
    buffer_t *buffer = lua_getdata(L, 1);

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    luaL_addchar(&b, '[');

    char hex_buffer[6];

    for (size_t i = 0; i < buffer->len; i++)
    {
        snprintf(hex_buffer, sizeof(hex_buffer), "0x%02X", buffer->data[i]);

        luaL_addstring(&b, hex_buffer);

        if (i < buffer->len - 1)
        {
            luaL_addchar(&b, ',');
        }
    }

    luaL_addchar(&b, ']');
    luaL_pushresult(&b);

    return 1;
}

DEF_FN(__eq)
{
    buffer_t *buffer1 = lua_getdata(L, 1);
    buffer_t *buffer2 = lua_getdata(L, 2);

    if (buffer1->len != buffer2->len)
        lua_pushboolean(L, 0);
    else
        lua_pushboolean(L, memcmp(buffer1->data, buffer2->data, buffer1->len) == 0);

    return 1;
}

DEF_FN(__len)
{
    buffer_t *buffer = lua_getdata(L, 1);
    lua_pushinteger(L, buffer->len);
    return 1;
}

DEF_FN(__concat)
{
    buffer_t *buffer1 = lua_getdata(L, 1);
    buffer_t *buffer2 = lua_getdata(L, 2);

    buffer_t *concat = create_buffer(L, buffer1->len + buffer2->len);
    memcpy(concat->data, buffer1->data, buffer1->len);
    memcpy(&concat->data[buffer1->len], buffer2->data, buffer2->len);

    return 1;
}

DEF_FN(print)
{
    buffer_t *buffer = lua_getdata(L, 1);

    for (size_t i = 0; i < buffer->len; i++)
    {
        printf("0x%02X ", buffer->data[i]);
    }
    printf("\n");

    return 0;
}

DEF_FN(slice)
{
    buffer_t *buffer = lua_getdata(L, 1);

    luaL_argcheck(L, lua_isnumber(L, 2), 2, "Expected number");

    int start = lua_tointeger(L, 2);
    int end = -1;

    if (lua_isnumber(L, 3))
    {
        end = lua_tointeger(L, 3);
    }

    if (end < 0)
    {
        end = buffer->len + end + 1;
    }

    if (start < 0 || start >= (int)buffer->len)
    {
        return luaL_error(L, "Index out of bounds: %d", start);
    }

    if (end < 0 || end > (int)buffer->len)
    {
        return luaL_error(L, "Index out of bounds: %d", end);
    }

    if (start > end)
    {
        return luaL_error(L, "Invalid range: %d > %d", start, end);
    }

    size_t len = end - start;
    buffer_t *slice = create_buffer(L, len);
    memcpy(slice->data, &buffer->data[start], len);

    return 1;
}

DEF_FN(reverse)
{
    buffer_t *buffer = lua_getdata(L, 1);

    for (size_t i = 0; i < buffer->len / 2; i++)
    {
        uint8_t temp = buffer->data[i];
        buffer->data[i] = buffer->data[buffer->len - i - 1];
        buffer->data[buffer->len - i - 1] = temp;
    }

    lua_pushvalue(L, 1);
    return 1;
}

DEF_FN(write)
{
    buffer_t *buffer = lua_getdata(L, 1);
    buffer_t *src = lua_getdata(L, 2);

    luaL_argcheck(L, lua_isnumber(L, 3), 3, "Expected number");

    int offset = lua_tointeger(L, 3);

    if (offset < 0 || offset >= (int)buffer->len)
    {
        return luaL_error(L, "Index out of bounds: %d", offset);
    }

    if (offset + src->len > buffer->len)
    {
        return luaL_error(L, "Buffer overflow: %d + %d > %d", offset, src->len, buffer->len);
    }

    memcpy(&buffer->data[offset], src->data, src->len);

    return 0;
}

DEF_FN(toutf8)
{
    buffer_t *buffer = lua_getdata(L, 1);

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    for (size_t i = 0; i < buffer->len; i++)
    {
        luaL_addchar(&b, buffer->data[i]);
    }

    luaL_pushresult(&b);

    return 1;
}

DEF_FN(resize)
{
    buffer_t *buffer = lua_getdata(L, 1);

    luaL_argcheck(L, lua_isnumber(L, 2), 2, "Expected number");

    size_t len = lua_tonumber(L, 2);
    if (len <= 0)
    {
        return luaL_error(L, "Invalid argument: expected positive number");
    }

    buffer->data = realloc(buffer->data, len);
    buffer->len = len;

    return 0;
}

DEF_FUNCS{
    FN(new),
    END_FN,
};

DEF_METHODS{
    FN(__gc),
    FN(__index),
    FN(__newindex),
    FN(__tostring),
    FN(__eq),
    FN(__len),
    FN(__concat),
    FN(print),
    FN(slice),
    FN(reverse),
    FN(write),
    FN(toutf8),
    FN(resize),
    END_FN,
};

DEF_LIB(buffer)
