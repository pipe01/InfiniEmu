#pragma once

#define PINS_COUNT 32

#include <stdbool.h>

typedef struct pins_t pins_t;

pins_t *pins_new();
void pins_free(pins_t *);

void pins_reset(pins_t *);

void pins_set(pins_t *, int pin);
void pins_clear(pins_t *, int pin);

bool pins_is_input(pins_t *, int pin);
void pins_set_input(pins_t *, int pin);
void pins_set_output(pins_t *, int pin);

bool pins_is_set(pins_t *, int pin);
