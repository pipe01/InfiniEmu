#include "components/spi/st7789.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fault.h"

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

enum
{
    RGB_FORMAT_12bpp = 3,
    RGB_FORMAT_16bpp = 5,
    RGB_FORMAT_18bpp = 6,
};

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
    bool on;
    bool sleeping;
    bool inverted;
    bool normal_mode;

    size_t write_counter;

    colmod_t colmod;
    value16_t xstart, xend, ystart, yend;
    value16_t vertical_scroll_start;

    command_t command;
    size_t expecting_data, got_data;
    uint8_t data_buffer[2048];

    uint8_t screen[DISPLAY_BUFFER_WIDTH * DISPLAY_BUFFER_HEIGHT * BYTES_PER_PIXEL];
    uint8_t *screen_buffer;
    size_t screen_buffer_ptr;
};

uint8_t st7789_read(void *userdata)
{
    fault_take(FAULT_NOT_IMPLEMENTED);
}

void st7789_write(uint8_t byte, void *userdata)
{
    st7789_t *st7789 = userdata;

    // Some commands will send extra data after the command byte, however this data comes
    // on a separate SPI write. When handling these commands we set the expecting_data to
    // the number of bytes we expect to receive.

    if (st7789->got_data < st7789->expecting_data)
    {
        if (st7789->got_data == sizeof(st7789->data_buffer))
            fault_take(FAULT_SPI_INPUT_BUFFER_FULL);

        st7789->data_buffer[st7789->got_data++] = byte;

        if (st7789->got_data == st7789->expecting_data)
        {
            switch (st7789->command)
            {
            case Command_WriteToRam:
            {
                memcpy(&st7789->screen_buffer[st7789->screen_buffer_ptr], st7789->data_buffer, st7789->got_data);

                st7789->expecting_data -= st7789->got_data;
                st7789->screen_buffer_ptr += st7789->got_data;

                if (st7789->expecting_data == 0)
                {
                    assert_fault(st7789->xend.value >= st7789->xstart.value, FAULT_ST7789_INVALID_COORDS);
                    assert_fault(st7789->yend.value >= st7789->ystart.value, FAULT_ST7789_INVALID_COORDS);
                    assert_fault(st7789->xstart.value < DISPLAY_BUFFER_WIDTH, FAULT_ST7789_INVALID_COORDS);
                    assert_fault(st7789->xend.value < DISPLAY_BUFFER_WIDTH, FAULT_ST7789_INVALID_COORDS);
                    assert_fault(st7789->ystart.value < DISPLAY_BUFFER_HEIGHT, FAULT_ST7789_INVALID_COORDS);
                    assert_fault(st7789->yend.value < DISPLAY_BUFFER_HEIGHT, FAULT_ST7789_INVALID_COORDS);

                    uint16_t width = st7789->xend.value - st7789->xstart.value + 1;
                    uint16_t height = st7789->yend.value - st7789->ystart.value + 1;
                    size_t stride = width * BYTES_PER_PIXEL;

                    // static int counter = 0;
                    // printf("WriteToRam %d: %d x %d starting at %d,%d\n", counter++, width, height, st7789->xstart.value, st7789->ystart.value);

                    size_t region_start_px = (DISPLAY_BUFFER_WIDTH * st7789->ystart.value) + st7789->xstart.value;

                    for (size_t row = 0; row < height; row++)
                    {
                        size_t start_px = region_start_px + row * DISPLAY_BUFFER_WIDTH;
                        size_t start = start_px * BYTES_PER_PIXEL;

                        assert(start + stride <= sizeof(st7789->screen));
                        assert(row * stride + stride <= st7789->screen_buffer_ptr);

                        memcpy(&st7789->screen[start], &st7789->screen_buffer[row * stride], stride);
                    }

                    free(st7789->screen_buffer);
                }
                break;
            }

            case Command_ColMod:
            {
                st7789->colmod = (colmod_t){.value = st7789->data_buffer[0]};

                assert(st7789->colmod.ctrl_color_format == 5);
                assert(st7789->colmod.rgb_color_format == RGB_FORMAT_16bpp);
                break;
            }

            case Command_MemoryDataAccessControl:
            {
                madctl_t madctl = (madctl_t){.value = st7789->data_buffer[0]};
                (void)madctl;

                assert(madctl.mh == 0);
                assert(madctl.rgb == 0);
                assert(madctl.ml == 0);
                assert(madctl.mv == 0);
                assert(madctl.mx == 0);
                assert(madctl.my == 0);
                break;
            }

            case Command_ColumnAddressSet:
                st7789->xstart.msb = st7789->data_buffer[0];
                st7789->xstart.lsb = st7789->data_buffer[1];
                st7789->xend.msb = st7789->data_buffer[2];
                st7789->xend.lsb = st7789->data_buffer[3];
                assert(st7789->xstart.value <= st7789->xend.value);
                break;

            case Command_RowAddressSet:
                st7789->ystart.msb = st7789->data_buffer[0];
                st7789->ystart.lsb = st7789->data_buffer[1];
                st7789->yend.msb = st7789->data_buffer[2];
                st7789->yend.lsb = st7789->data_buffer[3];
                assert(st7789->ystart.value <= st7789->yend.value);
                break;

            case Command_VdvSet:
                // Ignore
                break;

            case Command_VerticalScrollStartAddress:
                st7789->vertical_scroll_start.msb = st7789->data_buffer[0];
                st7789->vertical_scroll_start.lsb = st7789->data_buffer[1];
                break;

            default:
                fault_take(FAULT_SPI_UNKNOWN_COMMAND);
            }
        }

        return;
    }

    st7789->command = byte;
    st7789->got_data = 0;
    st7789->expecting_data = 0;

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

    case Command_NormalModeOn:
        st7789->normal_mode = true;
        break;

    case Command_VdvSet:
        st7789->expecting_data = 1;
        break;

    case Command_DisplayOn:
        st7789->on = true;
        break;

    case Command_DisplayOff:
        st7789->on = false;
        break;

    case Command_WriteToRam:
    {
        uint16_t width = st7789->xend.value - st7789->xstart.value + 1;
        uint16_t height = st7789->yend.value - st7789->ystart.value + 1;
        size_t bytes = width * height * BYTES_PER_PIXEL;

        assert(bytes > 0);

        st7789->expecting_data = bytes;
        st7789->screen_buffer = malloc(bytes);
        st7789->screen_buffer_ptr = 0;
        st7789->write_counter++;
        break;
    }

    case Command_VerticalScrollStartAddress:
        st7789->expecting_data = 2;
        break;

    default:
        // fault_take(FAULT_I2C_UNKNOWN_COMMAND);
        printf("Unknown ST7789 command: 0x%02X\n", st7789->command);
        break;
    }
}

void st7789_reset(void *userdata)
{
    st7789_t *st7789 = userdata;

    memset(st7789, 0, sizeof(st7789_t));
    st7789->sleeping = true;
}

void st7789_cs_changed(bool selected, void *userdata)
{
}

st7789_t *st7789_new()
{
    st7789_t *st7789 = malloc(sizeof(st7789_t));
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

void st7789_read_screen(st7789_t *st, uint8_t *data, size_t width, size_t height)
{
    assert(width == DISPLAY_BUFFER_WIDTH);
    assert(height <= DISPLAY_BUFFER_HEIGHT);

    size_t start = st->vertical_scroll_start.value * DISPLAY_BUFFER_WIDTH * BYTES_PER_PIXEL;
    size_t length = width * height * BYTES_PER_PIXEL;

    if (start + length > sizeof(st->screen))
    {
        // Wrap around

        memcpy(data, &st->screen[start], sizeof(st->screen) - start);
        memcpy(&data[sizeof(st->screen) - start], st->screen, length - (sizeof(st->screen) - start));
    }
    else
    {
        memcpy(data, &st->screen[start], length);
    }
}

bool st7789_is_sleeping(st7789_t *st)
{
    return st->sleeping;
}

size_t st7789_get_write_count(st7789_t *st)
{
    return st->write_counter;
}
