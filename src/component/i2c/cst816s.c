#include "components/i2c/cst816s.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "fault.h"

#define CHIPID 0xB4
#define VENDORID 0x00
#define FWVERSION 0x01

#define MAX_READ_SIZE 50

typedef struct __attribute__((packed))
{
    uint8_t _unknown;
    uint8_t gesture;
    uint8_t pointNum;
    uint8_t xHigh;
    uint8_t xLow;
    uint8_t yHigh;
    uint8_t yLow;
} touchdata_t;

struct cst816s_t
{
    struct state
    {
        uint8_t next_read[MAX_READ_SIZE];
        size_t next_read_size;

        touchdata_t touchdata;
        bool has_touch;
    };

    pins_t *pins;
    int irqPin;
};

void cst816s_reset(void *userdata)
{
    cst816s_t *cst816s = userdata;

    pins_set(cst816s->pins, cst816s->irqPin); // Active low
}

void cst816s_write(uint8_t *data, size_t data_size, void *userdata)
{
    cst816s_t *cst816s = (cst816s_t *)userdata;

    assert(data_size >= 1);

    uint8_t reg = data[0];

    switch (reg)
    {
    case 0x00: // Read touch data
    {
        if (cst816s->has_touch)
        {
            pins_set(cst816s->pins, cst816s->irqPin);
            cst816s->has_touch = false;
        }

        memcpy(cst816s->next_read, &cst816s->touchdata, sizeof(touchdata_t));
        cst816s->next_read_size = sizeof(touchdata_t);
        break;
    }

    case 0x15: // Unknown
        // Do nothing
        break;

    case 0xA5: // Sleep?
        // Do nothing
        break;

    case 0xA7: // ChipID
        cst816s->next_read[0] = CHIPID;
        cst816s->next_read_size = 1;
        cst816s->next_read_size = 1;
        break;

    case 0xA8: // VendorID
        cst816s->next_read[0] = VENDORID;
        cst816s->next_read_size = 1;
        break;

    case 0xA9: // FWVersion
        cst816s->next_read[0] = FWVERSION;
        cst816s->next_read_size = 1;
        break;

    case 0xEC: // MotionMask
        // Do nothing
        break;

    case 0xFA: // IrqCtl
        // Do nothing
        break;

    default:
        fault_take(FAULT_I2C_UNKNOWN_COMMAND);
    }
}

size_t cst816s_read(uint8_t *data, size_t data_size, void *userdata)
{
    cst816s_t *cst816s = (cst816s_t *)userdata;

    if (data_size > cst816s->next_read_size)
        return 0;

    memcpy(data, cst816s->next_read, data_size);

    return data_size;
}

cst816s_t *cst816s_new(pins_t *pins, state_store_t *store, int irqPin)
{
    cst816s_t *cst816s = calloc(1, sizeof(cst816s_t));
    cst816s->pins = pins;
    cst816s->irqPin = irqPin;

    state_store_register(store, STATE_KEY_CST816S, cst816s, sizeof(struct state));

    return cst816s;
}

i2c_slave_t cst816s_get_slave(cst816s_t *cst816s)
{
    return (i2c_slave_t){
        .userdata = cst816s,
        .write = cst816s_write,
        .read = cst816s_read,
        .reset = cst816s_reset,
    };
}

void cst816s_do_touch(cst816s_t *cst, touch_gesture_t gesture, uint16_t x, uint16_t y)
{
    cst->touchdata = (touchdata_t){
        .gesture = gesture,
        .pointNum = 1,
        .xHigh = (x >> 8) & 0xFF,
        .xLow = x & 0xFF,
        .yHigh = (y >> 8) & 0xFF,
        .yLow = y & 0xFF,
    };
    cst->has_touch = true;

    pins_clear(cst->pins, cst->irqPin);
}

void cst816s_release_touch(cst816s_t *cst)
{
    cst->touchdata = (touchdata_t){
        .gesture = GESTURE_NONE,
        .pointNum = 0,
    };
    cst->has_touch = true;

    pins_clear(cst->pins, cst->irqPin);
}
