#include "components/i2c/cst816s.h"

#include <assert.h>
#include <stdio.h>
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
    uint8_t event;
    uint8_t xHigh;
    uint8_t xLow;
    uint8_t id;
    uint8_t yHigh;
    uint8_t yLog;
    uint8_t step;
    uint8_t xy;
    uint8_t misc;
} touchdata_t;

typedef struct
{
    uint8_t next_read[MAX_READ_SIZE];
    size_t next_read_size;
} cst816s_t;

void cst816s_reset(void *userdata)
{
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
        touchdata_t data = {0};
        memcpy(cst816s->next_read, &data, sizeof(touchdata_t));
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

i2c_slave_t cst816s_new()
{
    cst816s_t *cst816s = (cst816s_t *)malloc(sizeof(cst816s_t));

    return (i2c_slave_t){
        .userdata = cst816s,
        .write = cst816s_write,
        .read = cst816s_read,
        .reset = cst816s_reset,
    };
}