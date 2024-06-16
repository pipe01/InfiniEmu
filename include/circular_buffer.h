#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct circular_buffer_t circular_buffer_t;

circular_buffer_t *circular_buffer_new(size_t size);
void circular_buffer_free(circular_buffer_t *);

bool circular_buffer_read(circular_buffer_t *, uint8_t *data);
bool circular_buffer_write(circular_buffer_t *, uint8_t data);
void circular_buffer_clear(circular_buffer_t *);
