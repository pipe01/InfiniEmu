#pragma once

#include "bus_i2c.h"
#include "pins.h"

typedef enum
{
    GESTURE_NONE = 0x00,
    GESTURE_SLIDEDOWN = 0x01,
    GESTURE_SLIDEUP = 0x02,
    GESTURE_SLIDELEFT = 0x03,
    GESTURE_SLIDERIGHT = 0x04,
    GESTURE_SINGLETAP = 0x05,
    GESTURE_DOUBLETAP = 0x0B,
    GESTURE_LONGPRESS = 0x0C,
} touch_gesture_t;

typedef struct cst816s_t cst816s_t;

cst816s_t *cst816s_new(pins_t *pins, int irqPin);
i2c_slave_t cst816s_get_slave(cst816s_t *);

void cst816s_do_touch(cst816s_t *, touch_gesture_t gesture, uint16_t x, uint16_t y);
void cst816s_release_touch(cst816s_t *);
