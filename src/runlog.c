#include "runlog.h"

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

struct runlog_t
{
    int fd;
    pthread_mutex_t mutex;
};

runlog_t *runlog_new(int fd)
{
    runlog_t *runlog = calloc(1, sizeof(runlog_t));
    runlog->fd = fd;

    pthread_mutex_init(&runlog->mutex, NULL);

    return runlog;
}

void runlog_record(runlog_t *runlog, runlog_event_t event)
{
    pthread_mutex_lock(&runlog->mutex);
    if (write(runlog->fd, &event, sizeof(event)) != sizeof(event))
    {
        perror("write");
        exit(1);
    }
    pthread_mutex_unlock(&runlog->mutex);
}
