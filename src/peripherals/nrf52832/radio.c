#include "peripherals/nrf52832/radio.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "byte_util.h"
#include "fault.h"
#include "nrf52832.h"
#include "peripherals/nrf52832/ppi.h"

// Assume a 200 byte transmission at 1Mbps with a 64MHz clock
#define STATE_CHANGE_TXRX_DELAY_HFCLK (200 * 8 * (64000000 / 1000000))
#define STATE_CHANGE_DELAY_HFCLK 100

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
    uint8_t ap[4];
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

static const char *radio_state_names[] = {
    "DISABLED",
    "RXRU",
    "RXIDLE",
    "RX",
    "RXDISABLE",
    "???",
    "???",
    "???",
    "???",
    "TXRU",
    "TXIDLE",
    "TX",
    "TXDISABLE",
};

struct RADIO_inst_t
{
    ticker_t *ticker;
    dma_t *dma;

    bool powered_on;
    radio_state_t state, next_state;
    inten_t inten;

    bool tx_sent_address, tx_sent_payload;
    bool rx_received_address, rx_received_payload;

    uint32_t mode;
    uint32_t txpower;
    uint32_t packetptr;
    uint32_t bcc;

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

    radio_rx_cb_t rx_cb; // TODO: Rename to TX
    void *rx_userdata;

    uint8_t rx_data[258];
    size_t rx_data_len;
};

void radio_set_rx_cb(RADIO_t *radio, radio_rx_cb_t cb, void *userdata)
{
    radio->rx_cb = cb;
    radio->rx_userdata = userdata;
}

void radio_reset(RADIO_t *radio)
{
    radio->powered_on = false;
    radio->state = STATE_DISABLED;
}

void radio_do_state_change(void *userdata)
{
    RADIO_t *radio = userdata;
    radio_state_t old_state = radio->state;
    uint32_t delay = STATE_CHANGE_DELAY_HFCLK;

    radio->state = radio->next_state;

    bool request_update = false;

    switch (radio->state)
    {
    case STATE_RXDISABLE:
    case STATE_TXDISABLE:
        radio->next_state = STATE_DISABLED;
        request_update = true;
        break;

    case STATE_TXRU:
        radio->next_state = STATE_TXIDLE;
        request_update = true;
        break;

    case STATE_RXRU:
        radio->next_state = STATE_RXIDLE;
        request_update = true;
        break;

    case STATE_TX:
        if (radio->tx_sent_address && radio->tx_sent_payload)
        {
            radio->tx_sent_address = false;
            radio->tx_sent_payload = false;
            radio->next_state = STATE_TXIDLE;
            delay = STATE_CHANGE_TXRX_DELAY_HFCLK;
        }
        else if (radio->tx_sent_address)
        {
            radio->tx_sent_payload = true;
            ppi_fire_event(current_ppi, INSTANCE_RADIO, EVENT_ID(RADIO_EVENTS_PAYLOAD), radio->inten.PAYLOAD);
        }
        else
        {
            radio->tx_sent_address = true;
            ppi_fire_event(current_ppi, INSTANCE_RADIO, EVENT_ID(RADIO_EVENTS_ADDRESS), radio->inten.ADDRESS);
        }
        request_update = true;
        break;

    case STATE_RX:
        if (radio->rx_received_address && radio->rx_received_payload)
        {
            radio->rx_received_address = false;
            radio->rx_received_payload = false;
            radio->next_state = STATE_RXIDLE;
            delay = STATE_CHANGE_TXRX_DELAY_HFCLK;
        }
        else if (radio->rx_received_address)
        {
            radio->rx_received_payload = true;
            ppi_fire_event(current_ppi, INSTANCE_RADIO, EVENT_ID(RADIO_EVENTS_PAYLOAD), radio->inten.PAYLOAD);
        }
        else
        {
            radio->rx_received_address = true;
            ppi_fire_event(current_ppi, INSTANCE_RADIO, EVENT_ID(RADIO_EVENTS_ADDRESS), radio->inten.ADDRESS);
        }
        request_update = true;
        break;

    default:
        switch (radio->next_state)
        {
        case STATE_DISABLED:
            if (old_state == STATE_TXDISABLE || old_state == STATE_RXDISABLE)
                ppi_fire_event(current_ppi, INSTANCE_RADIO, EVENT_ID(RADIO_EVENTS_DISABLED), radio->inten.DISABLED);
            break;

        case STATE_TXIDLE:
            if (old_state == STATE_TXRU)
                ppi_fire_event(current_ppi, INSTANCE_RADIO, EVENT_ID(RADIO_EVENTS_READY), radio->inten.READY);
            else if (old_state == STATE_TX)
                ppi_fire_event(current_ppi, INSTANCE_RADIO, EVENT_ID(RADIO_EVENTS_END), radio->inten.END);
            break;

        case STATE_RXIDLE:
            if (old_state == STATE_RXRU)
                ppi_fire_event(current_ppi, INSTANCE_RADIO, EVENT_ID(RADIO_EVENTS_READY), radio->inten.READY);
            else if (old_state == STATE_RX)
                ppi_fire_event(current_ppi, INSTANCE_RADIO, EVENT_ID(RADIO_EVENTS_END), radio->inten.END);
            break;

        default:
            break;
        }
        break;
    }

    printf("Radio state change: %s -> %s\n", radio_state_names[radio->state], radio_state_names[radio->next_state]);

    if (request_update)
        ticker_add(radio->ticker, CLOCK_HFCLK, radio_do_state_change, radio, delay, false);
}

static const char *radio_task_names[] = {
    [RADIO_TASKS_TXEN] = "TXEN",
    [RADIO_TASKS_RXEN] = "RXEN",
    [RADIO_TASKS_START] = "START",
    [RADIO_TASKS_STOP] = "STOP",
    [RADIO_TASKS_DISABLE] = "DISABLE",
    [RADIO_TASKS_RSSISTART] = "RSSISTART",
    [RADIO_TASKS_RSSISTOP] = "RSSISTOP",
    [RADIO_TASKS_BCSTART] = "BCSTART",
    [RADIO_TASKS_BCSTOP] = "BCSTOP",
};

PPI_TASK_HANDLER(radio_task_handler)
{
    RADIO_t *radio = userdata;

    printf("Radio task: %s\n", radio_task_names[task * 4]);

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
            if (radio->rx_cb)
            {
                uint8_t packet[256];
                dma_read(radio->dma, radio->packetptr, 256, packet);

                size_t ptr = 0;

                uint8_t s0[radio->pcnf0.S0LEN];
                memcpy(s0, &packet[ptr], radio->pcnf0.S0LEN);
                ptr += radio->pcnf0.S0LEN;

                uint16_t length = READ_UINT16(packet, ptr);
                length &= (1 << radio->pcnf0.LFLEN) - 1;
                ptr += (radio->pcnf0.LFLEN + 7) / 8; // Round up to the nearest byte

                if (radio->pcnf0.S1LEN > 0)
                {
                    fault_take(FAULT_NOT_IMPLEMENTED);
                }
                else if (radio->pcnf0.S1INCL == 1)
                {
                    ptr++;
                }

                uint8_t payload[length];
                memcpy(payload, &packet[ptr], length);

                uint8_t address[4];

                assert(radio->pcnf1.BALEN == 3);

                switch (radio->txaddress)
                {
                case 0:
                    WRITE_UINT32(address, 0, radio->base0 >> 8);
                    address[3] = radio->prefix0.ap[0];
                    break;

                default:
                    WRITE_UINT32(address, 0, radio->base1 >> 8);
                    address[3] = radio->prefix1.ap[radio->txaddress & 7];
                    break;
                }

                uint8_t crc[3] = {0}; // TODO: Implement CRC

                // Excludes preamble
                uint8_t ll_packet[sizeof(address) + radio->pcnf0.S0LEN + sizeof(length) + sizeof(payload) + sizeof(crc)];
                uint8_t *packet_ptr = ll_packet;

                memcpy(packet_ptr, address, sizeof(address));
                packet_ptr += sizeof(address);

                memcpy(packet_ptr, s0, radio->pcnf0.S0LEN);
                packet_ptr += radio->pcnf0.S0LEN;

                int length_bytes = (radio->pcnf0.LFLEN + 7) / 8;
                memcpy(packet_ptr, &length, length_bytes);
                packet_ptr += length_bytes;

                memcpy(packet_ptr, payload, sizeof(payload));
                packet_ptr += sizeof(payload);

                memcpy(packet_ptr, crc, sizeof(crc));
                packet_ptr += sizeof(crc);

                radio->rx_cb(radio->rx_userdata, ll_packet, sizeof(ll_packet));
            }

            radio->next_state = STATE_TX;
            break;

        case STATE_RXIDLE:
            radio->next_state = radio->rx_data_len > 0 ? STATE_RX : STATE_RXIDLE;
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
        break;

    case TASK_ID(RADIO_TASKS_BCSTART):
    case TASK_ID(RADIO_TASKS_BCSTOP):
        // TODO: fault_take(FAULT_NOT_IMPLEMENTED);
        break;
    }

    if (radio->next_state != radio->state)
        ticker_add(radio->ticker, CLOCK_HFCLK, radio_do_state_change, radio, STATE_CHANGE_DELAY_HFCLK, false);
}

OPERATION(radio)
{
    RADIO_t *radio = (RADIO_t *)userdata;

    if (op == OP_RESET)
    {
        radio_reset(radio);
        return MEMREG_RESULT_OK;
    }

    OP_IGNORE_LOAD_DATA // TODO: Implement
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
        OP_ASSERT_SIZE(op, WORD);

        if (op == OP_READ_WORD)
        {
            *value = radio->shorts.value;
        }
        else if (op == OP_WRITE_WORD)
        {
            radio->shorts.value = *value;

            ppi_shorts_set_enabled(current_ppi, SHORT_RADIO_READY_START, radio->shorts.READY_START);
            ppi_shorts_set_enabled(current_ppi, SHORT_RADIO_END_DISABLE, radio->shorts.END_DISABLE);
            ppi_shorts_set_enabled(current_ppi, SHORT_RADIO_DISABLED_TXEN, radio->shorts.DISABLED_TXEN);
            ppi_shorts_set_enabled(current_ppi, SHORT_RADIO_DISABLED_RXEN, radio->shorts.DISABLED_RXEN);
            ppi_shorts_set_enabled(current_ppi, SHORT_RADIO_ADDRESS_RSSISTART, radio->shorts.ADDRESS_RSSISTART);
            ppi_shorts_set_enabled(current_ppi, SHORT_RADIO_END_START, radio->shorts.END_START);
            ppi_shorts_set_enabled(current_ppi, SHORT_RADIO_ADDRESS_BCSTART, radio->shorts.ADDRESS_BCSTART);
            ppi_shorts_set_enabled(current_ppi, SHORT_RADIO_DISABLED_RSSISTOP, radio->shorts.DISABLED_RSSISTOP);
        }

        return (MEMREG_RESULT_OK);

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

    case 0x560: // BCC
        OP_RETURN_REG(radio->bcc, WORD);

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
    RADIO_t *radio = calloc(1, sizeof(RADIO_t));
    radio->ticker = ctx.ticker;
    radio->dma = ctx.dma;

    ppi_add_peripheral(ctx.ppi, ctx.id, radio_task_handler, radio);

    return radio;
}
