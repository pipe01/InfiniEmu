#include "event_queue.h"

#include <stdlib.h>

typedef struct
{
    event_type_t type;
    void *data;
} event_t;

const char *event_type_str[] = {
    "radio_message",
};

#define CAPACITY 16

struct event_queue_t
{
    event_t events[CAPACITY];
    size_t head;
    size_t tail;
};

event_queue_t *event_queue_new()
{
    return calloc(1, sizeof(event_queue_t));
}

void event_queue_free(event_queue_t *queue)
{
    free(queue);
}

void event_queue_add(event_queue_t *queue, event_type_t ev, void *data)
{
    if ((queue->tail + 1) % CAPACITY == queue->head)
    {
        return;
    }

    queue->events[queue->tail].type = ev;
    queue->events[queue->tail].data = data;
    queue->tail = (queue->tail + 1) % CAPACITY;
}

bool event_queue_poll(event_queue_t *queue, event_type_t *ev, void **data)
{
    if (queue->head == queue->tail)
    {
        return false;
    }

    *ev = queue->events[queue->head].type;
    *data = queue->events[queue->head].data;
    queue->head = (queue->head + 1) % CAPACITY;

    return true;
}
