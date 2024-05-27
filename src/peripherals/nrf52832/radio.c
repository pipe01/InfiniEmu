#include "peripherals/nrf52832/radio.h"

#include <assert.h>
#include <stdlib.h>

enum
{
    TASKS_TXEN = 0x000,
    TASKS_RXEN = 0x004,
    TASKS_START = 0x008,
    TASKS_STOP = 0x00C,
    TASKS_DISABLE = 0x010,
    TASKS_RSSISTART = 0x014,
    TASKS_RSSISTOP = 0x018,
    TASKS_BCSTART = 0x01C,
    TASKS_BCSTOP = 0x020,
    EVENTS_READY = 0x100,
    EVENTS_ADDRESS = 0x104,
    EVENTS_PAYLOAD = 0x108,
    EVENTS_END = 0x10C,
    EVENTS_DISABLED = 0x110,
    EVENTS_DEVMATCH = 0x114,
    EVENTS_DEVMISS = 0x118,
    EVENTS_RSSIEND = 0x11C,
    EVENTS_BCMATCH = 0x128,
    EVENTS_CRCOK = 0x130,
    EVENTS_CRCERROR = 0x134,
};

typedef union
{
    struct
    {
        unsigned int READY : 1;
        unsigned int ADDRESS : 1;
        unsigned int PAYLOAD : 1;
        unsigned int END : 1;
        unsigned int DISABLED : 1;
        unsigned int DEVMATCH : 1;
        unsigned int DEVMISS : 1;
        unsigned int RSSIEND : 1;
        unsigned int : 2;
        unsigned int BCMATCH : 1;
        unsigned int : 1;
        unsigned int CRCOK : 1;
        unsigned int CRCERROR : 1;
    };
    uint32_t value;
} inten_t;
static_assert(sizeof(inten_t) == 4, "inten_t size is not 4 bytes");

typedef union
{
    struct
    {
        unsigned int LFLEN : 4;
        unsigned int : 4;
        unsigned int S0LEN : 1;
        unsigned int : 7;
        unsigned int S1LEN : 4;
        unsigned int S1INCL : 1;
        unsigned int : 3;
        unsigned int PLEN : 1;
    };
    uint32_t value;
} pcnf0_t;
static_assert(sizeof(pcnf0_t) == 4, "pcnf0_t size is not 4 bytes");

typedef union
{
    struct
    {
        unsigned int MAXLEN : 8;
        unsigned int STATLEN : 8;
        unsigned int BALEN : 3;
        unsigned int : 5;
        unsigned int ENDIAN : 1;
        unsigned int WHITEEN : 1;
    };
    uint32_t value;
} pcnf1_t;
static_assert(sizeof(pcnf1_t) == 4, "pcnf1_t size is not 4 bytes");

typedef union
{
    struct
    {
        unsigned int RU : 1;
        unsigned int : 7;
        unsigned int DTX : 2;
    };
    uint32_t value;
} modecnf0_t;
static_assert(sizeof(modecnf0_t) == 4, "modecnf0_t size is not 4 bytes");

typedef union
{
    struct
    {
        unsigned int LEN : 2;
        unsigned int : 6;
        unsigned int SKIPADDR : 1;
    };
    uint32_t value;
} crccnf_t;

struct RADIO_inst_t
{
    bool powered_on;
    inten_t inten;

    uint32_t mode;

    pcnf0_t pcnf0;
    pcnf1_t pcnf1;
    modecnf0_t modecnf0;

    uint32_t txaddress, rxaddresses;

    crccnf_t crccnf;
    uint32_t crcinit, crcpoly;

    uint32_t tifs;
};

void radio_reset(RADIO_t *radio)
{
    radio->powered_on = false;
}

OPERATION(radio)
{
    RADIO_t *radio = (RADIO_t *)userdata;

    if (op == OP_RESET)
    {
        radio_reset(radio);
        return MEMREG_RESULT_OK;
    }

    OP_ASSERT_SIZE(op, WORD);

    switch (offset)
    {
    case 0x304: // INTENSET
        if (OP_IS_READ(op))
            *value = radio->inten.value;
        else
            radio->inten.value |= *value;
        return MEMREG_RESULT_OK;

    case 0x308: // INTENCLR
        if (OP_IS_READ(op))
            *value = radio->inten.value;
        else
            radio->inten.value &= ~*value;
        return MEMREG_RESULT_OK;

    case 0x510: // MODE
        OP_RETURN_REG(radio->mode, WORD);

    case 0x514: // PCNF0
        OP_RETURN_REG(radio->pcnf0.value, WORD);

    case 0x518: // PCNF1
        OP_RETURN_REG(radio->pcnf1.value, WORD);

    case 0x52C: // TXADDRESS
        OP_RETURN_REG(radio->txaddress, WORD);

    case 0x530: // RXADDRESSES
        OP_RETURN_REG(radio->rxaddresses, WORD);

    case 0x534: // CRCCNF
        OP_RETURN_REG(radio->crccnf.value, WORD);

    case 0x538: // CRCPOLY
        OP_RETURN_REG(radio->crcpoly, WORD);

    case 0x53C: // CRCINIT
        OP_RETURN_REG(radio->crcinit, WORD);

    case 0x544: // TIFS
        OP_RETURN_REG(radio->tifs, WORD);

    case 0x650: // MODECNF0
        OP_RETURN_REG(radio->modecnf0.value, WORD);

    case 0x73C: // Undocumented
        *value = 0x00003090;
        return MEMREG_RESULT_OK;

    case 0xFFC: // POWER
        if (OP_IS_READ(op))
        {
            *value = radio->powered_on ? 1 : 0;
            return MEMREG_RESULT_OK;
        }

        if (*value && !radio->powered_on)
            radio_reset(radio);

        radio->powered_on = *value & 1;
        return MEMREG_RESULT_OK;
    }

    return MEMREG_RESULT_UNHANDLED;
}

NRF52_PERIPHERAL_CONSTRUCTOR(RADIO, radio)
{
    return (RADIO_t *)malloc(sizeof(RADIO_t));
}
