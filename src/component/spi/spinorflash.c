#include "components/spi/spinorflash.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "circular_buffer.h"
#include "config.h"
#include "fault.h"

#if ENABLE_LOG_SPI_FLASH
#define LOGF(...) printf(__VA_ARGS__)
#else
#define LOGF(...)
#endif

enum
{
    COMMAND_PP = 0x02,    // Page Program
    COMMAND_READ = 0x03,  // Read Data Bytes
    COMMAND_RDSR = 0x05,  // Read Status Register
    COMMAND_WREN = 0x06,  // Write Enable
    COMMAND_SE = 0x20,    // Sector Erase
    COMMAND_RDSER = 0x2B, // Read Security Register - not sure if this is correct
    COMMAND_RDID = 0x9F,  // Read Identification
    COMMAND_RDI = 0xAB,   // Release from Deep Power-Down and Read Device ID
};

#define MAX_COMMAND_SIZE 200
#define READ_QUEUE_SIZE 512

#define READ_UINT24(data, start) (((data)[(start)] << 16) | ((data)[(start) + 1] << 8) | (data)[(start) + 2])

typedef union
{
    struct
    {
        unsigned int WIP : 1;  // Write in progress
        unsigned int WEL : 1;  // Write enable latch
        unsigned int BP0 : 1;  // Block protect 0
        unsigned int BP1 : 1;  // Block protect 1
        unsigned int BP2 : 1;  // Block protect 2
        unsigned int BP3 : 1;  // Block protect 3
        unsigned int BP4 : 1;  // Block protect 4
        unsigned int SRP0 : 1; // Status register protect
        unsigned int SRP1 : 1; // Status register protect
        unsigned int QE : 1;   // Quad enable
        unsigned int LB : 1;   // Security register lock
        unsigned int : 3;
        unsigned int CMP : 1; // Complement protect
    };
    uint16_t value;
} statusreg_t;

typedef union
{
    struct
    {
        // I haven't been able to find information on this register so these fields were extracted from InfiniTime's code

        unsigned int : 4;
        unsigned int PRFAIL : 1; // Program failed
        unsigned int ERFAIL : 1; // Erase failed
    };
    uint8_t value;
} securityreg_t;

struct spinorflash_t
{
    uint8_t *data;
    size_t size, sector_size;

    bool should_free_data;

    size_t write_count;

    statusreg_t statusreg;
    securityreg_t securityreg;

    uint8_t last_write[MAX_COMMAND_SIZE];
    size_t last_write_size;
    bool handled_command;

    bool is_reading_data;
    uint32_t data_read_address;

    circular_buffer_t *out_buffer;

    uint32_t pp_address;
};

void spinorflash_write_internal(uint8_t byte, void *userdata)
{
    LOGF("SPI flash got data: %02X\n", byte);

    spinorflash_t *flash = (spinorflash_t *)userdata;

    if (flash->statusreg.WIP)
    {
        flash->data[flash->pp_address++] = byte;
        flash->write_count++;
        return;
    }

    flash->is_reading_data = false;
    flash->last_write[flash->last_write_size++] = byte;

    switch (flash->last_write_size)
    {
    case 1:
        switch (flash->last_write[0])
        {
        case COMMAND_RDID:
            circular_buffer_write(flash->out_buffer, 0x0B);
            circular_buffer_write(flash->out_buffer, 0x40);
            circular_buffer_write(flash->out_buffer, 0x16);
            flash->handled_command = true;
            break;

        case COMMAND_RDSR:
            circular_buffer_write(flash->out_buffer, flash->statusreg.value & 0xFF);
            flash->handled_command = true;
            break;

        case COMMAND_RDSER:
            circular_buffer_write(flash->out_buffer, flash->securityreg.value);
            flash->handled_command = true;
            break;

        case COMMAND_WREN:
            flash->statusreg.WEL = 1;
            flash->handled_command = true;
            break;
        }
        break;

    case 4:
        switch (flash->last_write[0])
        {
        case COMMAND_PP:
        {
            assert(flash->statusreg.WEL);

            uint32_t addr = READ_UINT24(flash->last_write, 1);
            assert(addr < flash->size);

            flash->pp_address = addr;
            flash->statusreg.WIP = 1;
            flash->handled_command = true;
            break;
        }

        case COMMAND_RDI:
            circular_buffer_write(flash->out_buffer, 0xA5);
            flash->handled_command = true;
            break;

        case COMMAND_READ:
        {
            flash->data_read_address = READ_UINT24(flash->last_write, 1);
            flash->is_reading_data = true;
            flash->handled_command = true;
            break;
        }

        case COMMAND_SE:
        {
            assert(flash->statusreg.WEL);

            uint32_t addr = READ_UINT24(flash->last_write, 1);
            assert(addr <= flash->size - flash->sector_size);

            memset(flash->data + addr, 0xFF, flash->sector_size);
            flash->write_count++;
            flash->handled_command = true;
            break;
        }
        }
        break;
    }
}

uint8_t spinorflash_read_internal(void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;

    if (flash->is_reading_data)
        return flash->data[flash->data_read_address++];

    uint8_t byte;

    if (circular_buffer_read(flash->out_buffer, &byte))
        return byte;

    return 0xFF;
}

void spinorflash_cs_changed(bool selected, void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;

    if (!selected)
    {
        if (!flash->handled_command && flash->last_write_size > 0 && flash->last_write[0] == COMMAND_RDI)
        {
            // Release from power-down
            puts("");
        }
        else if (flash->last_write_size > 0 && !flash->handled_command)
        {
            abort();
        }

        if (flash->last_write_size > 0 && (flash->last_write[0] == COMMAND_PP || flash->last_write[0] == COMMAND_SE))
            flash->statusreg.WEL = 0;

        flash->statusreg.WIP = 0;
        flash->last_write_size = 0;
    }
    else
    {
        flash->handled_command = false;
    }
}

void spinorflash_reset(void *userdata)
{
    spinorflash_t *flash = (spinorflash_t *)userdata;

    flash->statusreg.value = 0;
    flash->securityreg.value = 0;
    flash->last_write_size = 0;
    flash->write_count = 0;

    circular_buffer_clear(flash->out_buffer);
}

spinorflash_t *spinorflash_new(size_t size, size_t sector_size)
{
    spinorflash_t *flash = malloc(sizeof(spinorflash_t));
    flash->data = malloc(size);
    flash->should_free_data = true;
    flash->size = size;
    flash->sector_size = sector_size;
    flash->out_buffer = circular_buffer_new(READ_QUEUE_SIZE);

    return flash;
}

spi_slave_t spinorflash_get_slave(spinorflash_t *flash)
{
    return (spi_slave_t){
        .userdata = flash,
        .read = spinorflash_read_internal,
        .write = spinorflash_write_internal,
        .reset = spinorflash_reset,
        .cs_changed = spinorflash_cs_changed,
    };
}

size_t spinorflash_get_write_count(spinorflash_t *flash)
{
    return flash->write_count;
}

void spinorflash_set_buffer(spinorflash_t *flash, uint8_t *data)
{
    if (flash->should_free_data)
        free(flash->data);

    flash->should_free_data = false;
    flash->data = data;
}
