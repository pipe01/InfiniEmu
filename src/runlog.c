#include "runlog.h"

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

typedef enum
{
    RUNLOG_EV_RESET = 1,
    RUNLOG_EV_LOAD_PROGRAM,
    RUNLOG_EV_FETCH_INST,
    RUNLOG_EV_EXECUTE_INST,
    RUNLOG_EV_MEMORY_LOAD,
    RUNLOG_EV_MEMORY_STORE,
    RUNLOG_EV_EXCEPTION_ENTER,
    RUNLOG_EV_EXCEPTION_EXIT,
} __attribute__((__packed__)) runlog_ev_type;
static_assert(sizeof(runlog_ev_type) == 1, "runlog_ev_type size is not 1 byte");

struct runlog_t
{
    FILE *file;

    runlog_registers_t regs;
};

runlog_t *runlog_new(FILE *file)
{
    runlog_t *runlog = calloc(1, sizeof(runlog_t));
    runlog->file = file;

    return runlog;
}

void runlog_free(runlog_t *runlog)
{
    fflush(runlog->file);
    free(runlog);
}

static void runlog_write(runlog_t *runlog, const void *buf, size_t n)
{
    if (fwrite(buf, n, 1, runlog->file) == 0)
    {
        perror("write");
        exit(1);
    }
}

static inline void runlog_write_type(runlog_t *runlog, runlog_ev_type type)
{
    runlog_write(runlog, &type, sizeof(type));
}

static void runlog_write_regs(runlog_t *runlog, runlog_registers_t regs)
{
    for (uint8_t i = RUNLOG_REG_MIN; i <= RUNLOG_REG_MAX; i++)
    {
        if (regs.core[i] != runlog->regs.core[i])
        {
            runlog_write(runlog, &i, sizeof(i));
            runlog_write(runlog, &regs.core[i], sizeof(regs.core[i]));
        }
    }

    runlog->regs = regs;
    runlog_write(runlog, &(uint8_t){0xff}, sizeof(uint8_t));
}

void runlog_record_reset(runlog_t *runlog, runlog_registers_t regs)
{
    runlog_write_type(runlog, RUNLOG_EV_RESET);
    runlog_write_regs(runlog, regs);
}

void runlog_record_load_program(runlog_t *runlog, uint8_t *program, uint32_t size)
{
    runlog_write_type(runlog, RUNLOG_EV_LOAD_PROGRAM);
    runlog_write(runlog, &size, sizeof(size));
    runlog_write(runlog, program, size);
}

void runlog_record_fetch(runlog_t *runlog, uint32_t pc)
{
    runlog_write_type(runlog, RUNLOG_EV_FETCH_INST);
    runlog_write(runlog, &pc, sizeof(pc));
}

void runlog_record_execute(runlog_t *runlog, runlog_registers_t regs)
{
    runlog_write_type(runlog, RUNLOG_EV_EXECUTE_INST);
    runlog_write_regs(runlog, regs);
}

void runlog_record_memory_load(runlog_t *runlog, uint32_t addr, uint32_t value, runlog_register_t dst, byte_size_t size)
{
    static_assert(sizeof(size) == 1, "size is not 1 byte");
    static_assert(sizeof(dst) == 1, "dst is not 1 byte");

    runlog_write_type(runlog, RUNLOG_EV_MEMORY_LOAD);
    runlog_write(runlog, &addr, sizeof(addr));
    runlog_write(runlog, &value, sizeof(value));
    runlog_write(runlog, &dst, sizeof(dst));
    runlog_write(runlog, &size, sizeof(size));
}

void runlog_record_memory_store(runlog_t *runlog, runlog_register_t src, uint32_t value, uint32_t addr, byte_size_t size)
{
    static_assert(sizeof(size) == 1, "size is not 1 byte");
    static_assert(sizeof(src) == 1, "src is not 1 byte");

    runlog_write_type(runlog, RUNLOG_EV_MEMORY_STORE);
    runlog_write(runlog, &src, sizeof(src));
    runlog_write(runlog, &value, sizeof(value));
    runlog_write(runlog, &addr, sizeof(addr));
    runlog_write(runlog, &size, sizeof(size));
}

void runlog_exception_enter(runlog_t *runlog, uint16_t ex_num)
{
    runlog_write_type(runlog, RUNLOG_EV_EXCEPTION_ENTER);
    runlog_write(runlog, &ex_num, sizeof(ex_num));
}

void runlog_exception_exit(runlog_t *runlog, uint16_t ex_num)
{
    runlog_write_type(runlog, RUNLOG_EV_EXCEPTION_EXIT);
    runlog_write(runlog, &ex_num, sizeof(ex_num));
}
