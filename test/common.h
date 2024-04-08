#include "cpu.h"

#include <stdint.h>

#define ADD_MEM(start, mem) mem_first = *(mem_last == NULL ? &mem_first : &mem_last->next) = (mem)
#define ADD_MEM_SIMPLE(start, data) ADD_MEM(start, memreg_new_simple(start, data, sizeof(data)))
