#pragma once

#include "pinetime.h"

void run_lua(const char *script, size_t script_size, const char *name, pinetime_t *pt);
void run_lua_file(const char *script_path, pinetime_t *pt);
