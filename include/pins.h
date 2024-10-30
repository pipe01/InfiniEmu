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

typedef enum
{
    PIN_INPUT = 0,
    PIN_OUTPUT = 1,
    PIN_PULLDOWN = 2,
    PIN_PULLUP = 4,
} pindir_t;

typedef enum
{
    PINOWNER_NONE = 0,
    PINOWNER_GPIOTE = 1 << 0,

    PINOWNER_ANY = ~0,
} pinowner_t;

#define pins_is_input(pins, pin) ((pins_get_dir(pins, pin) & 1) == 0)
#define pins_set_input(pins, pin) pins_set_dir(pins, pin, pins_get_dir(pins, pin) & ~PIN_OUTPUT)
#define pins_set_output(pins, pin) pins_set_dir(pins, pin, pins_get_dir(pins, pin) | PIN_OUTPUT)

pins_t *pins_new(void);
void pins_free(pins_t *);

void pins_reset(pins_t *);

void pins_set(pins_t *, int pin);
void pins_clear(pins_t *, int pin);
void pins_toggle(pins_t *, int pin);

pindir_t pins_get_dir(pins_t *, int pin);
void pins_set_dir(pins_t *, int pin, pindir_t dir);

void pins_set_sense(pins_t *, int pin, pinsense_t sense);
pinsense_t pins_get_sense(pins_t *, int pin);

uint32_t pins_get_latch(pins_t *);
void pins_set_latch(pins_t *, uint32_t latch);

bool pins_is_set(pins_t *, int pin);
uint32_t pins_read_all(pins_t *);

bool pins_acquire(pins_t *, int pin, pinowner_t owner);
bool pins_release(pins_t *, int pin, pinowner_t owner);
bool pins_is_owned(pins_t *, int pin, pinowner_t owner);
