#include "pins.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    bool is_set;
    bool is_input;
    bool pull_down;
    bool pull_up;

    pinsense_t sense;
} pin_t;

struct pins_t
{
    pin_t pins[PINS_COUNT];

    uint32_t latch;
    static_assert(PINS_COUNT == 32);
};

pins_t *pins_new()
{
    return (pins_t *)calloc(1, sizeof(pins_t));
}

void pins_free(pins_t *pins)
{
    free(pins);
}

void pins_reset(pins_t *pins)
{
    memset(pins, 0, sizeof(pins_t));
}

static inline void pins_set_state(pins_t *pins, int pin, bool is_set)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    pin_t *p = &pins->pins[pin];
    if (p->is_set == is_set)
        return;

    p->is_set = is_set;

    if (p->sense != SENSE_DISABLED && ((is_set && (p->sense == SENSE_HIGH)) || (!is_set && (p->sense == SENSE_LOW))))
        pins->latch |= 1 << pin;
}

void pins_set(pins_t *pins, int pin)
{
    pins_set_state(pins, pin, true);
}

void pins_clear(pins_t *pins, int pin)
{
    pins_set_state(pins, pin, false);
}

void pins_toggle(pins_t *pins, int pin)
{
    pins_set_state(pins, pin, !pins_is_set(pins, pin));
}

bool pins_is_set(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    return pins->pins[pin].is_set;
}

bool pins_is_input(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    return pins->pins[pin].is_input;
}

void pins_set_input(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    pins->pins[pin].is_input = true;
}

void pins_set_output(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    pins->pins[pin].is_input = false;
}

void pins_set_sense(pins_t *pins, int pin, pinsense_t sense)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    pins->pins[pin].sense = sense;
}

pinsense_t pins_get_sense(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    return pins->pins[pin].sense;
}

uint32_t pins_get_latch(pins_t *pins)
{
    return pins->latch;
}

void pins_set_latch(pins_t *pins, uint32_t latch)
{
    pins->latch = latch;
}
