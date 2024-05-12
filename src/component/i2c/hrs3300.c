#include "components/i2c/hrs3300.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_READ_SIZE 100

typedef struct
{
    uint8_t enable, pdriver, res, hgain;

    uint8_t next_read[MAX_READ_SIZE];
    size_t next_read_size;
} hrs3300_t;

void hrs3300_reset(void *userdata)
{
    hrs3300_t *hrs3300 = (hrs3300_t *)userdata;
    hrs3300->enable = 0x68;
}

void hrs3300_write(uint8_t *data, size_t data_size, void *userdata)
{
    hrs3300_t *hrs3300 = (hrs3300_t *)userdata;

    uint8_t reg = data[0];

    switch (reg)
    {
    case 0x01: // ENABLE
        RETURN_REG(hrs3300, enable);
        break;

    case 0x0C: // PDRIVER
        RETURN_REG(hrs3300, pdriver);
        break;

    case 0x16: // RES
        RETURN_REG(hrs3300, res);
        break;

    case 0x17: // HGAIN
        RETURN_REG(hrs3300, hgain);
        break;

    default:
        abort();
    }
}

size_t hrs3300_read(uint8_t *data, size_t data_size, void *userdata)
{
    hrs3300_t *hrs3300 = (hrs3300_t *)userdata;

    assert(data_size >= hrs3300->next_read_size);

    memcpy(data, hrs3300->next_read, data_size);

    return data_size;
}

i2c_slave_t hrs3300_new()
{
    hrs3300_t *hrs3300 = (hrs3300_t *)malloc(sizeof(hrs3300_t));

    return (i2c_slave_t){
        .userdata = hrs3300,
        .write = hrs3300_write,
        .read = hrs3300_read,
        .reset = hrs3300_reset,
    };
}
