#pragma once

#define CLEAR_AFTER(type, ptr, field) memset((ptr) + offsetof(type, field) + sizeof((ptr)->field), 0, sizeof(type) - offsetof(type, field) - sizeof((ptr)->field))
