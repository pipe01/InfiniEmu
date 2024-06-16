#include "circular_buffer.h"

#include <stdlib.h>

struct circular_buffer_t
{
    uint8_t *data;
    size_t size;
    size_t head;
    size_t tail;
};

circular_buffer_t *circular_buffer_new(size_t size)
{
    circular_buffer_t *buf = malloc(sizeof(circular_buffer_t));
    buf->data = malloc(size);
    buf->size = size;
    buf->head = buf->tail = 0;

    return buf;
}

void circular_buffer_free(circular_buffer_t *buf)
{
    free(buf->data);
    free(buf);
}

bool circular_buffer_read(circular_buffer_t *buf, uint8_t *data)
{
    if (buf->head == buf->tail)
        return false;

    *data = buf->data[buf->tail];
    buf->tail = (buf->tail + 1) % buf->size;

    return true;
}

bool circular_buffer_write(circular_buffer_t *buf, uint8_t data)
{
    size_t next_head = (buf->head + 1) % buf->size;

    if (next_head == buf->tail)
        return false;

    buf->data[buf->head] = data;
    buf->head = next_head;

    return true;
}

void circular_buffer_clear(circular_buffer_t *buf)
{
    buf->head = buf->tail = 0;
}
