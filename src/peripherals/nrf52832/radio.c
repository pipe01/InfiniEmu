#include "peripherals/nrf52832/radio.h"

#include <assert.h>
#include <stdlib.h>

#include "fault.h"
#include "peripherals/nrf52832/ppi.h"

#define STATE_CHANGE_DELAY_INST 10000

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

typedef union
{
    struct
    {
        unsigned int READY_START : 1;
        unsigned int END_DISABLE : 1;
        unsigned int DISABLED_TXEN : 1;
        unsigned int DISABLED_RXEN : 1;
        unsigned int ADDRESS_RSSISTART : 1;
        unsigned int END_START : 1;
        unsigned int ADDRESS_BCSTART : 1;
        unsigned int : 1;
        unsigned int DISABLED_RSSISTOP : 1;
    };
    uint32_t value;
} shorts_t;
static_assert(sizeof(shorts_t) == 4, "shorts_t size is not 4 bytes");

typedef union
{
    uint8_t byte[4];
    uint32_t value;
} prefix_t;

typedef union
{
    struct
    {
        unsigned int FREQUENCY : 7;
        unsigned int : 1;
        unsigned int MAP : 1;
    };
    uint32_t value;
} frequency_t;

typedef enum
{
    STATE_DISABLED = 0,   // No operations are going on inside the radio and the power consumption is at a minimum
    STATE_RXRU = 1,       // The radio is ramping up and preparing for reception
    STATE_RXIDLE = 2,     // The radio is ready for reception to start
    STATE_RX = 3,         // Reception has been started and the addresses enabled in the RXADDRESSES register are being monitored
    STATE_RXDISABLE = 4,  // The radio is disabling the receiver
    STATE_TXRU = 9,       // The radio is ramping up and preparing for transmission
    STATE_TXIDLE = 10,    // The radio is ready for transmission to start
    STATE_TX = 11,        // The radio is transmitting a packet
    STATE_TXDISABLE = 12, // The radio is disabling the transmitter
} radio_state_t;

struct RADIO_inst_t
{
    ticker_t *ticker;

    bool powered_on;
    radio_state_t state, next_state;
    inten_t inten;

    uint32_t mode;
    uint32_t txpower;
    uint32_t packetptr;

    pcnf0_t pcnf0;
    pcnf1_t pcnf1;
    modecnf0_t modecnf0;
    shorts_t shorts;

    frequency_t frequency;

    uint32_t base0, base1;
    prefix_t prefix0, prefix1;
    uint32_t txaddress, rxaddresses;

    crccnf_t crccnf;
    uint32_t crcinit, crcpoly;

    uint32_t datawhiteiv;

    uint32_t tifs;
};

void radio_reset(RADIO_t *radio)
{
    radio->powered_on = false;
    radio->state = STATE_DISABLED;
}

void radio_do_state_change(void *userdata)
{
    RADIO_t *radio = userdata;

    radio->state = radio->next_state;

    switch (radio->state)
    {
    case STATE_RXDISABLE:
    case STATE_TXDISABLE:
        radio->next_state = STATE_DISABLED;
        break;

    case STATE_TXRU:
        radio->next_state = STATE_TXIDLE;
        break;

    case STATE_RXRU:
        radio->next_state = STATE_RXIDLE;
        break;

    default:
        break;
    }

    if (radio->next_state != radio->state)
        ticker_add(radio->ticker, radio_do_state_change, radio, STATE_CHANGE_DELAY_INST, false);
}

PPI_TASK_HANDLER(radio_task_handler)
{
    RADIO_t *radio = userdata;

    switch (task)
    {
    case TASK_ID(RADIO_TASKS_STOP):
        switch (radio->state)
        {
        case STATE_TX:
            radio->next_state = STATE_TXIDLE;
            break;
        case STATE_RX:
            radio->next_state = STATE_RXIDLE;
            break;
        default:
            break;
        }
        break;

    case TASK_ID(RADIO_TASKS_TXEN):
        switch (radio->state)
        {
        case STATE_DISABLED:
            radio->next_state = STATE_TXRU;
            break;
        default:
            break;
        }
        break;

    case TASK_ID(RADIO_TASKS_RXEN):
        switch (radio->state)
        {
        case STATE_DISABLED:
            radio->next_state = STATE_RXRU;
            break;
        default:
            break;
        }
        break;

    case TASK_ID(RADIO_TASKS_START):
        switch (radio->state)
        {
        case STATE_TXIDLE:
            radio->next_state = STATE_TX;
            break;
        case STATE_RXIDLE:
            radio->next_state = STATE_RX;
            break;
        default:
            break;
        }
        break;

    case TASK_ID(RADIO_TASKS_DISABLE):
        switch (radio->state)
        {
        case STATE_TX:
        case STATE_TXIDLE:
        case STATE_TXRU:
            radio->next_state = STATE_TXDISABLE;
            break;
        case STATE_RX:
        case STATE_RXIDLE:
        case STATE_RXRU:
            radio->next_state = STATE_RXDISABLE;
            break;
        default:
            break;
        }
        break;

    case TASK_ID(RADIO_TASKS_RSSISTART):
    case TASK_ID(RADIO_TASKS_RSSISTOP):
    case TASK_ID(RADIO_TASKS_BCSTART):
    case TASK_ID(RADIO_TASKS_BCSTOP):
        fault_take(FAULT_NOT_IMPLEMENTED);
    }

    if (radio->next_state != radio->state)
        ticker_add(radio->ticker, radio_do_state_change, radio, STATE_CHANGE_DELAY_INST, false);
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
        OP_TASK(RADIO_TASKS_TXEN)
        OP_TASK(RADIO_TASKS_RXEN)
        OP_TASK(RADIO_TASKS_START)
        OP_TASK(RADIO_TASKS_STOP)
        OP_TASK(RADIO_TASKS_DISABLE)
        OP_TASK(RADIO_TASKS_RSSISTART)
        OP_TASK(RADIO_TASKS_RSSISTOP)
        OP_TASK(RADIO_TASKS_BCSTART)
        OP_TASK(RADIO_TASKS_BCSTOP)
        OP_EVENT(RADIO_EVENTS_READY)
        OP_EVENT(RADIO_EVENTS_ADDRESS)
        OP_EVENT(RADIO_EVENTS_PAYLOAD)
        OP_EVENT(RADIO_EVENTS_END)
        OP_EVENT(RADIO_EVENTS_DISABLED)
        OP_EVENT(RADIO_EVENTS_DEVMATCH)
        OP_EVENT(RADIO_EVENTS_DEVMISS)
        OP_EVENT(RADIO_EVENTS_RSSIEND)
        OP_EVENT(RADIO_EVENTS_BCMATCH)
        OP_EVENT(RADIO_EVENTS_CRCOK)
        OP_EVENT(RADIO_EVENTS_CRCERROR)

    case 0x200: // SHORTS
        OP_RETURN_REG(radio->shorts.value, WORD);

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

    case 0x504: // PACKETPTR
        OP_RETURN_REG(radio->packetptr, WORD);

    case 0x508: // FREQUENCY
        OP_RETURN_REG(radio->frequency.value, WORD);

    case 0x50C: // TXPOWER
        OP_RETURN_REG(radio->txpower, WORD);

    case 0x510: // MODE
        OP_RETURN_REG(radio->mode, WORD);

    case 0x514: // PCNF0
        OP_RETURN_REG(radio->pcnf0.value, WORD);

    case 0x518: // PCNF1
        OP_RETURN_REG(radio->pcnf1.value, WORD);

    case 0x51C: // BASE0
        OP_RETURN_REG(radio->base0, WORD);

    case 0x520: // BASE1
        OP_RETURN_REG(radio->base1, WORD);

    case 0x524: // PREFIX0
        OP_RETURN_REG(radio->prefix0.value, WORD);

    case 0x528: // PREFIX1
        OP_RETURN_REG(radio->prefix1.value, WORD);

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

    case 0x550: // STATE
        OP_ASSERT_READ(op);
        *value = radio->state;
        return MEMREG_RESULT_OK;

    case 0x554: // DATAWHITEIV
        OP_RETURN_REG(radio->datawhiteiv, WORD);

    case 0x650: // MODECNF0
        OP_RETURN_REG(radio->modecnf0.value, WORD);

    case 0x73C: // Undocumented
        *value = 0x00003090;
        return MEMREG_RESULT_OK;

    case 0x774: // Undocumented, used on errata 102, 106, 107
        if (OP_IS_READ(op))
            *value = 0;
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
    RADIO_t *radio = malloc(sizeof(RADIO_t));
    radio->ticker = ctx.ticker;

    ppi_add_peripheral(ctx.ppi, ctx.id, radio_task_handler, radio);

    return radio;
}
