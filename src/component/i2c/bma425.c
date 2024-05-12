#include "components/i2c/bma425.h"

#include <assert.h>
#include <stdlib.h>

#define CHIPID 0x13

#define RETURN_REG(reg)                      \
    do                                       \
    {                                        \
        if (data_size == 1)                  \
            bma425->next_read = bma425->reg; \
        else                                 \
            bma425->reg = data[1];           \
    } while (0)

typedef struct
{
    uint8_t pwr_conf, int_latch, init_ctrl, features_in;

    uint8_t next_read;
} bma425_t;

void bma425_reset(void *userdata)
{
    bma425_t *bma425 = (bma425_t *)userdata;

    bma425->pwr_conf = 0x03;
}

void bma425_write(uint8_t *data, size_t data_size, void *userdata)
{
    bma425_t *bma425 = (bma425_t *)userdata;

    assert(data_size >= 1);

    uint8_t reg = data[0];

    switch (reg)
    {
    case 0x00: // CHIP_ID
        bma425->next_read = CHIPID;
        break;

    case 0x55: // INT_LATCH
        RETURN_REG(int_latch);
        break;

    case 0x59: // INIT_CTRL
        RETURN_REG(init_ctrl);
        break;

    case 0x5A:
    case 0x5B:
    case 0x5C:
    case 0x5D:
        assert(data_size == 2);

        // Reserved, do nothing
        break;

    case 0x5E: // FEATURES_IN
        RETURN_REG(features_in);
        break;

    case 0x7C: // PWR_CONF
        RETURN_REG(pwr_conf);
        break;

    case 0x7E: // CMD
        assert(data_size == 2);

        // Do nothing
        break;

    default:
        abort();
    }
}

size_t bma425_read(uint8_t *data, size_t data_size, void *userdata)
{
    bma425_t *bma425 = (bma425_t *)userdata;

    assert(data_size == 1);

    *data = bma425->next_read;
    return 1;
}

i2c_slave_t bma425_new()
{
    bma425_t *bma425 = (bma425_t *)malloc(sizeof(bma425_t));

    return (i2c_slave_t){
        .userdata = bma425,
        .write = bma425_write,
        .read = bma425_read,
        .reset = bma425_reset,
    };
}