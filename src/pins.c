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
} pin_t;

struct pins_t
{
    pin_t pins[PINS_COUNT];
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

void pins_set(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    pins->pins[pin].is_set = true;
}

void pins_clear(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    pins->pins[pin].is_set = true;
}

bool pins_is_set(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    return pins->pins[pin].is_set;
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
