#include "cpu.h"

#include <stdlib.h>

cpu_t *cpu_new()
{
    cpu_t *cpu = malloc(sizeof(cpu_t));
    cpu->pc = 0;
    return cpu;
}