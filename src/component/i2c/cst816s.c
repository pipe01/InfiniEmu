#include "components/i2c/cst816s.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define CHIPID 0xB4
#define VENDORID 0x00
#define FWVERSION 0x01

typedef struct
{
    uint8_t next_read;
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
    case 0x15: // Unknown
        // Do nothing
        break;

    case 0xA5: // Sleep?
        // Do nothing
        break;

    case 0xA7: // ChipID
        cst816s->next_read = CHIPID;
        break;

    case 0xA8: // VendorID
        cst816s->next_read = VENDORID;
        break;

    case 0xA9: // FWVersion
        cst816s->next_read = FWVERSION;
        break;

    case 0xEC: // MotionMask
        // Do nothing
        break;

    case 0xFA: // IrqCtl
        // Do nothing
        break;

    default:
        abort();
    }
}

size_t cst816s_read(uint8_t *data, size_t data_size, void *userdata)
{
    cst816s_t *cst816s = (cst816s_t *)userdata;
    
    assert(data_size == 1);

    *data = cst816s->next_read;
    return 1;
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