#include "components/i2c/bma425.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bus_i2c.h"
#include "config.h"

#define CHIPID 0x13

#define MAX_READ_SIZE 100

static const uint8_t features_default[] = {
    0x00, 0xAA, // any_motion settings_1
    0x00, 0x05, // any_motion settings_2
    0x01, 0x2D, // step_counter settings_1
    0x7B, 0xD4, // step_counter settings_2
    0x01, 0x3B, // step_counter settings_3
    0x7A, 0xDB, // step_counter settings_4
    0x00, 0x04, // step_counter settings_5
    0x7B, 0x4F, // step_counter settings_6
    0x6C, 0xCD, // step_counter settings_7
    0x04, 0xC3, // step_counter settings_8
    0x09, 0x85, // step_counter settings_9
    0x04, 0xC3, // step_counter settings_10
    0xE6, 0xEC, // step_counter settings_11
    0x46, 0x0C, // step_counter settings_12
    0x00, 0x01, // step_counter settings_13
    0x00, 0x27, // step_counter settings_14
    0x00, 0x19, // step_counter settings_15
    0x00, 0x96, // step_counter settings_16
    0x00, 0xA0, // step_counter settings_17
    0x00, 0x01, // step_counter settings_18
    0x00, 0x0C, // step_counter settings_19
    0x3C, 0xF0, // step_counter settings_20
    0x01, 0x00, // step_counter settings_21
    0x00, 0x01, // step_counter settings_22
    0x00, 0x03, // step_counter settings_23
    0x00, 0x01, // step_counter settings_24
    0x00, 0x0E, // step_counter settings_25
    0x00, 0x00, // step_counter settings_26
    0x00, 0x06, // tap_doubletap
    0x00, 0x00, // wrist_tilt
    0x00, 0x00, // general_settings
};

#define FEATURES_SIZE (sizeof(features_default))

typedef union
{
    struct
    {
        unsigned int lsb : 4;
        unsigned int msb : 8;
    };
    uint16_t value;
} addr16_t;

typedef struct
{
    uint8_t pwr_conf, pwr_ctrl, int_latch, init_ctrl, internal_status, acc_conf, acc_range;
    uint8_t reserved[2];
    addr16_t features_start_addr;

    uint8_t features_in[FEATURES_SIZE];
    uint8_t unknown[4096];

    struct
    {
        uint16_t x, y, z;
    } acc;

    uint32_t step_counter;
    uint8_t temperature, activity_type;

    uint8_t next_read[MAX_READ_SIZE];
    size_t next_read_size;
} bma425_t;

void bma425_reset(void *userdata)
{
    bma425_t *bma425 = (bma425_t *)userdata;
    memset(bma425, 0, sizeof(bma425_t));

    bma425->pwr_conf = 0x03;
    bma425->init_ctrl = 0x90;
}

void bma425_write(uint8_t *data, size_t data_size, void *userdata)
{
    bma425_t *bma425 = (bma425_t *)userdata;

    assert(data_size >= 1);

    uint8_t reg = data[0];

#ifdef ENABLE_LOG_BMA425
    printf("BMA425 got data: ");
    for (size_t i = 0; i < data_size; i++)
    {
        printf("%02X", data[i]);
        if (i < data_size - 1)
            printf("-");
    }
    printf("\n");
#endif

    switch (reg)
    {
    case 0x00: // CHIP_ID
        assert(data_size == 1);

        bma425->next_read[0] = CHIPID;
        bma425->next_read_size = 1;
        break;

    case 0x12: // DATA_8 (ACC_X LSB)
        assert(data_size == 1);

        memcpy(bma425->next_read, &bma425->acc, sizeof(bma425->acc));
        bma425->next_read_size = sizeof(bma425->acc);
        break;

    case 0x1E: // STEP_COUNTER_0
        assert(data_size == 1);

        memcpy(bma425->next_read, &bma425->step_counter, sizeof(bma425->step_counter));
        bma425->next_read_size = sizeof(bma425->step_counter);
        break;

    case 0x22: // TEMPERATURE
        assert(data_size == 1);

        bma425->next_read[0] = bma425->temperature;
        bma425->next_read_size = 1;
        break;

    case 0x27: // ACTIVITY_TYPE
        assert(data_size == 1);

        bma425->next_read[0] = bma425->activity_type;
        bma425->next_read_size = 1;
        break;

    case 0x2A: // INTERNAL_STATUS
        RETURN_REG(bma425, internal_status);
        break;

    case 0x40: // ACC_CONF
        RETURN_REG(bma425, acc_conf);
        break;

    case 0x41: // ACC_RANGE
        RETURN_REG(bma425, acc_range);
        break;

    case 0x55: // INT_LATCH
        RETURN_REG(bma425, int_latch);
        break;

    case 0x59: // INIT_CTRL
        if (data_size == 1)
        {
            bma425->next_read[0] = bma425->init_ctrl;
            bma425->next_read_size = 1;
        }
        else
        {
            assert(data_size == 2);

            bma425->init_ctrl = data[1];

            if (data[1] & 0x01)
                bma425->internal_status |= 0x01;
        }
        break;

    case 0x5A: // Reserved
        RETURN_REG(bma425, reserved[0]);
        break;

    case 0x5B: // Reserved
        RETURN_REG(bma425, features_start_addr.lsb);
        break;

    case 0x5C: // Reserved
        RETURN_REG(bma425, features_start_addr.msb);
        break;

    case 0x5D: // Reserved
        RETURN_REG(bma425, reserved[1]);
        break;

    case 0x5E: // FEATURES_IN
        if (data_size == 1)
        {
            bma425->next_read_size = 16;
            memcpy(bma425->next_read, bma425->unknown + bma425->features_start_addr.value, 16);
        }
        else
        {
            memcpy(bma425->unknown + bma425->features_start_addr.value, data + 1, data_size - 1);
        }
        break;

    case 0x7C: // PWR_CONF
        RETURN_REG(bma425, pwr_conf);
        break;

    case 0x7D: // PWR_CTRL
        RETURN_REG(bma425, pwr_ctrl);
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

    assert(data_size <= bma425->next_read_size);

    memcpy(data, bma425->next_read, data_size);
    return data_size;
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