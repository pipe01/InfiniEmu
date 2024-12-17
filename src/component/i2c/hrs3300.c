#include "components/i2c/hrs3300.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fault.h"

#define MAX_READ_SIZE 100

struct hrs3300_t
{
    uint8_t enable, pdriver, res, hgain;

    uint8_t next_read[MAX_READ_SIZE];
    size_t next_read_size;

    uint32_t ch0, ch1;
};

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

    case 0x08: // C1DATAM
        assert_fault(data_size == 1, FAULT_I2C_INVALID_DATA);
        hrs3300->next_read[0] = (hrs3300->ch1 >> 3) & 0xFF;
        hrs3300->next_read_size = 1;
        break;

    case 0x09: // C0DATAM
        assert_fault(data_size == 1, FAULT_I2C_INVALID_DATA);
        hrs3300->next_read[0] = (hrs3300->ch0 >> 8) & 0xFF;
        hrs3300->next_read_size = 1;
        break;

    case 0x0A: // C0DATAH
        assert_fault(data_size == 1, FAULT_I2C_INVALID_DATA);
        hrs3300->next_read[0] = (hrs3300->ch0 >> 4) & 0xF;
        hrs3300->next_read_size = 1;
        break;

    case 0x0C: // PDRIVER
        RETURN_REG(hrs3300, pdriver);
        break;

    case 0x0D: // C1DATAH
        assert_fault(data_size == 1, FAULT_I2C_INVALID_DATA);
        hrs3300->next_read[0] = (hrs3300->ch1 >> 11) & 0x7F;
        hrs3300->next_read_size = 1;
        break;

    case 0x0E: // C1DATAL
        assert_fault(data_size == 1, FAULT_I2C_INVALID_DATA);
        hrs3300->next_read[0] = hrs3300->ch1 & 0x7;
        hrs3300->next_read_size = 1;
        break;

    case 0x0F: // C0DATAL
        assert_fault(data_size == 1, FAULT_I2C_INVALID_DATA);
        hrs3300->next_read[0] = (hrs3300->ch0 & 0xF) | (((hrs3300->ch0 >> 16) & 0x3) << 4);
        hrs3300->next_read_size = 1;
        break;

    case 0x16: // RES
        RETURN_REG(hrs3300, res);
        break;

    case 0x17: // HGAIN
        RETURN_REG(hrs3300, hgain);
        break;

    default:
        printf("hrs3300: unknown register 0x%02x\n", reg);
        fault_take(FAULT_I2C_UNKNOWN_COMMAND);
    }
}

size_t hrs3300_read(uint8_t *data, size_t data_size, void *userdata)
{
    hrs3300_t *hrs3300 = (hrs3300_t *)userdata;

    assert(data_size >= hrs3300->next_read_size);

    memcpy(data, hrs3300->next_read, data_size);

    return data_size;
}

hrs3300_t *hrs3300_new(state_store_t *store)
{
    hrs3300_t *hrs = calloc(1, sizeof(hrs3300_t));

    state_store_register(store, STATE_KEY_HRS3300, hrs, sizeof(hrs3300_t));

    return hrs;
}

i2c_slave_t hrs3300_get_slave(hrs3300_t *hrs3300)
{
    return (i2c_slave_t){
        .userdata = hrs3300,
        .write = hrs3300_write,
        .read = hrs3300_read,
        .reset = hrs3300_reset,
    };
}

void hrs3300_set_ch0(hrs3300_t *hrs, uint32_t value)
{
    hrs->ch0 = value & 0xFFFFFF;
}

void hrs3300_set_ch1(hrs3300_t *hrs, uint32_t value)
{
    hrs->ch1 = value & 0xFFFFFF;
}
