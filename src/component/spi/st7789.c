#include "components/spi/st7789.h"

#include <assert.h>
#include <stdlib.h>

typedef enum
{
    Command_SoftwareReset = 0x01,
    Command_SleepIn = 0x10,
    Command_SleepOut = 0x11,
    Command_NormalModeOn = 0x13,
    Command_DisplayInversionOff = 0x20,
    Command_DisplayInversionOn = 0x21,
    Command_DisplayOff = 0x28,
    Command_DisplayOn = 0x29,
    Command_ColumnAddressSet = 0x2a,
    Command_RowAddressSet = 0x2b,
    Command_WriteToRam = 0x2c,
    Command_MemoryDataAccessControl = 0x36,
    Command_VerticalScrollDefinition = 0x33,
    Command_VerticalScrollStartAddress = 0x37,
    Command_ColMod = 0x3a,
    Command_VdvSet = 0xc4,
} command_t;

typedef union
{
    struct
    {
        unsigned int ctrl_color_format : 3;
        unsigned int : 1;
        unsigned int rgb_color_format : 3;
    };
    uint8_t value;
} colmod_t;

typedef union
{
    struct
    {
        unsigned int : 2;
        unsigned int mh : 1;  // Display Data Latch Order
        unsigned int rgb : 1; // RGB/BGR Order
        unsigned int ml : 1;  // Line Address Order
        unsigned int mv : 1;  // Page/Column Order
        unsigned int mx : 1;  // Column Address Order
        unsigned int my : 1;  // Page Address Order
    };
    uint8_t value;
} madctl_t; // Memory Data Access Control

typedef union
{
    struct
    {
        unsigned int lsb : 8;
        unsigned int msb : 8;
    };
    uint16_t value;
} value16_t;

struct st7789_t
{
    bool sleeping;
    bool inverted;

    value16_t xstart, xend, ystart, yend;

    command_t command;
    size_t expecting_data;
};

size_t st7789_read(uint8_t *data, size_t data_size, void *userdata)
{
    abort(); // TODO: Implement
}

void st7789_write(const uint8_t *data, size_t data_size, void *userdata)
{
    st7789_t *st7789 = (st7789_t *)userdata;

    assert(data_size >= 1);

    if (st7789->expecting_data)
    {
        assert(data_size == 1);

        switch (st7789->command)
        {
        case Command_ColMod:
        {
            colmod_t colmod = (colmod_t){.value = data[0]};

            assert(colmod.ctrl_color_format == 5);
            assert(colmod.rgb_color_format == 5);
            break;
        }

        case Command_MemoryDataAccessControl:
        {
            madctl_t madctl = (madctl_t){.value = data[0]};

            assert(madctl.mh == 0);
            assert(madctl.rgb == 0);
            assert(madctl.ml == 0);
            assert(madctl.mv == 0);
            assert(madctl.mx == 0);
            assert(madctl.my == 0);
            break;
        }

        case Command_ColumnAddressSet:
            switch (st7789->expecting_data)
            {
            case 4:
                st7789->xstart.msb = data[0];
                break;

            case 3:
                st7789->xstart.lsb = data[0];
                break;

            case 2:
                st7789->xend.msb = data[0];
                break;

            case 1:
                st7789->xend.lsb = data[0];
                break;

            default:
                abort();
            }
            break;

        case Command_RowAddressSet:
            switch (st7789->expecting_data)
            {
            case 4:
                st7789->ystart.msb = data[0];
                break;

            case 3:
                st7789->ystart.lsb = data[0];
                break;

            case 2:
                st7789->yend.msb = data[0];
                break;

            case 1:
                st7789->yend.lsb = data[0];
                break;

            default:
                abort();
            }
            break;

        default:
            abort();
        }

        st7789->expecting_data--;
        return;
    }

    assert(data_size == 1);

    st7789->command = data[0];

    switch (st7789->command)
    {
    case Command_SoftwareReset:
        // TODO: Implement?
        break;

    case Command_SleepIn:
        st7789->sleeping = true;
        break;

    case Command_SleepOut:
        st7789->sleeping = false;
        break;

    case Command_ColMod:
    case Command_MemoryDataAccessControl:
        st7789->expecting_data = 1;
        break;

    case Command_ColumnAddressSet:
    case Command_RowAddressSet:
        st7789->expecting_data = 4;
        break;
    
    case Command_DisplayInversionOff:
        st7789->inverted = false;
        break;
    
    case Command_DisplayInversionOn:
        st7789->inverted = true;
        break;

    default:
        abort();
    }
}

void st7789_reset(void *userdata)
{
}

void st7789_cs_changed(bool selected, void *userdata)
{
}

st7789_t *st7789_new()
{
    st7789_t *st7789 = (st7789_t *)malloc(sizeof(st7789_t));
    return st7789;
}

spi_slave_t st7789_get_slave(st7789_t *st7789)
{
    return (spi_slave_t){
        .userdata = st7789,
        .read = st7789_read,
        .write = st7789_write,
        .reset = st7789_reset,
        .cs_changed = st7789_cs_changed,
    };
}
