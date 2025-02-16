#pragma once

#include "lualibs.h"

typedef struct buffer_t buffer_t;

int l_buffer_new_copy(lua_State *L);

uint8_t *buffer_get_data(buffer_t *);
size_t buffer_get_len(buffer_t *);
