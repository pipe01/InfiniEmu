#include "pins.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct
{
    pindir_t dir;
    pinsense_t sense;
    pinowner_t owner;
    uint16_t voltage; // mV
    bool analog;
} pin_t;

struct pins_t
{
    uint16_t high_voltage_mv, high_threshold_mv;

    pin_t pins[PINS_COUNT];
    uint32_t pin_states;
    static_assert(PINS_COUNT == 32, "PINS_COUNT is not 32");

    uint32_t latch;
};

pins_t *pins_new(state_store_t *store, uint16_t high_voltage_mv, uint16_t high_threshold_mv)
{
    pins_t *pins = calloc(1, sizeof(pins_t));
    pins->high_threshold_mv = high_threshold_mv;
    pins->high_voltage_mv = high_voltage_mv;

    state_store_register(store, STATE_KEY_PINS, pins, sizeof(pins_t));

    return pins;
}

void pins_free(pins_t *pins)
{
    free(pins);
}

void pins_reset(pins_t *pins)
{
    pins->latch = 0;
}

void pins_set_voltage(pins_t *pins, int pin, uint16_t mv)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    bool is_set = mv >= pins->high_threshold_mv;
    bool was_set = pins_is_set(pins, pin);

    pin_t *p = &pins->pins[pin];

    pins->pin_states = (pins->pin_states & ~(1 << pin)) | (is_set << pin);
    pins->pins[pin].voltage = mv;

    if (was_set != is_set && p->sense != SENSE_DISABLED && ((is_set && (p->sense == SENSE_HIGH)) || (!is_set && (p->sense == SENSE_LOW))))
        pins->latch |= 1 << pin;
}

void pins_set(pins_t *pins, int pin)
{
    pins_set_voltage(pins, pin, pins->high_voltage_mv);
}

void pins_clear(pins_t *pins, int pin)
{
    pins_set_voltage(pins, pin, 0);
}

void pins_toggle(pins_t *pins, int pin)
{
    pins_set_voltage(pins, pin, pins_is_set(pins, pin) ? 0 : pins->high_voltage_mv);
}

bool pins_is_set(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    return (pins->pin_states & (1 << pin)) != 0;
}

bool pins_is_analog(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    return pins->pins[pin].analog;
}

void pins_set_analog(pins_t *pins, int pin, bool analog)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    printf("Setting pin %d to %s\n", pin, analog ? "analog" : "digital");
    pins->pins[pin].analog = analog;
}

uint16_t pins_get_voltage(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    return pins->pins[pin].voltage;
}

uint32_t pins_read_all(pins_t *pins)
{
    return pins->pin_states;
}

pindir_t pins_get_dir(pins_t *pins, int pin)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    return pins->pins[pin].dir;
}

void pins_set_dir(pins_t *pins, int pin, pindir_t dir)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    pins->pins[pin].dir = dir;
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

bool pins_acquire(pins_t *pins, int pin, pinowner_t owner)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    if (pins->pins[pin].owner != PINOWNER_NONE && pins->pins[pin].owner != owner)
        return false;

    pins->pins[pin].owner = owner;
    return true;
}

bool pins_release(pins_t *pins, int pin, pinowner_t owner)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    if (pins->pins[pin].owner == owner)
    {
        pins->pins[pin].owner = PINOWNER_NONE;
        return true;
    }

    return false;
}

bool pins_is_owned(pins_t *pins, int pin, pinowner_t owner)
{
    assert(pin >= 0 && pin < PINS_COUNT);

    return pins->pins[pin].owner == owner;
}
