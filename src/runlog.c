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
    RUNLOG_EV_MEMORY_WRITE,
} __attribute__((__packed__)) runlog_ev_type;
static_assert(sizeof(runlog_ev_type) == 1);

struct runlog_t
{
    int fd;
    pthread_mutex_t mutex;

    runlog_registers_t regs;
};

runlog_t *runlog_new(int fd)
{
    runlog_t *runlog = calloc(1, sizeof(runlog_t));
    runlog->fd = fd;

    pthread_mutex_init(&runlog->mutex, NULL);

    return runlog;
}

void runlog_free(runlog_t *runlog)
{
    pthread_mutex_destroy(&runlog->mutex);
    free(runlog);
}

static void runlog_write(runlog_t *runlog, const void *buf, size_t n)
{
    pthread_mutex_lock(&runlog->mutex);
    if (write(runlog->fd, buf, n) != (ssize_t)n)
    {
        perror("write");
        exit(1);
    }
    pthread_mutex_unlock(&runlog->mutex);
}

static void runlog_write_type(runlog_t *runlog, runlog_ev_type type)
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