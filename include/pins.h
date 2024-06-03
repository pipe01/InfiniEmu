#pragma once

#define PINS_COUNT 32

#include <stdbool.h>
#include <stdint.h>

typedef struct pins_t pins_t;

typedef enum
{
    SENSE_DISABLED = 0,
    SENSE_HIGH = 2,
    SENSE_LOW = 3
} pinsense_t;

pins_t *pins_new(void);
void pins_free(pins_t *);

void pins_reset(pins_t *);

void pins_set(pins_t *, int pin);
void pins_clear(pins_t *, int pin);
void pins_toggle(pins_t *, int pin);

bool pins_is_input(pins_t *, int pin);
void pins_set_input(pins_t *, int pin);
void pins_set_output(pins_t *, int pin);

void pins_set_sense(pins_t *, int pin, pinsense_t sense);
pinsense_t pins_get_sense(pins_t *, int pin);

uint32_t pins_get_latch(pins_t *);
void pins_set_latch(pins_t *, uint32_t latch);

bool pins_is_set(pins_t *, int pin);
