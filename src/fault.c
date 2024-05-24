#include "fault.h"

#include <stddef.h>
#include <stdlib.h>

_Thread_local jmp_buf *current_jmp = NULL;

void fault_set_jmp(jmp_buf *buf)
{
    current_jmp = buf;
}

void fault_clear_jmp()
{
    current_jmp = NULL;
}

void fault_take(fault_type_t t)
{
    if (current_jmp)
        longjmp(*current_jmp, t);
    else
        abort();
}
