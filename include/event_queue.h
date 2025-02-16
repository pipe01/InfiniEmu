#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct event_queue_t event_queue_t;

typedef enum
{
    EVENT_RADIO_MESSAGE,
} event_type_t;

extern const char *event_type_str[];

typedef struct
{
    uint8_t data[256];
    size_t len;
} event_radio_message_t;

event_queue_t *event_queue_new();
void event_queue_free(event_queue_t *);

void event_queue_add(event_queue_t *, event_type_t ev, void *data);
bool event_queue_poll(event_queue_t *, event_type_t *ev, void **data);
bool event_queue_peek(event_queue_t *);
