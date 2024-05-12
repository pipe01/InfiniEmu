#include "components/spi/st7789.h"

#include <assert.h>
#include <stdlib.h>

struct st7789_t
{
    uint32_t foo;
};

size_t st7789_read(uint8_t *data, size_t data_size, void *userdata)
{
    st7789_t *st7789 = (st7789_t *)userdata;
    (void)st7789;

    return 0;
}

void st7789_write(const uint8_t *data, size_t data_size, void *userdata)
{
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
