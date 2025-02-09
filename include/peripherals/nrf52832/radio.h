#pragma once

#include "peripherals/peripheral.h"

enum
{
    RADIO_TASKS_TXEN = 0x000,
    RADIO_TASKS_RXEN = 0x004,
    RADIO_TASKS_START = 0x008,
    RADIO_TASKS_STOP = 0x00C,
    RADIO_TASKS_DISABLE = 0x010,
    RADIO_TASKS_RSSISTART = 0x014,
    RADIO_TASKS_RSSISTOP = 0x018,
    RADIO_TASKS_BCSTART = 0x01C,
    RADIO_TASKS_BCSTOP = 0x020,
    RADIO_EVENTS_READY = 0x100,
    RADIO_EVENTS_ADDRESS = 0x104,
    RADIO_EVENTS_PAYLOAD = 0x108,
    RADIO_EVENTS_END = 0x10C,
    RADIO_EVENTS_DISABLED = 0x110,
    RADIO_EVENTS_DEVMATCH = 0x114,
    RADIO_EVENTS_DEVMISS = 0x118,
    RADIO_EVENTS_RSSIEND = 0x11C,
    RADIO_EVENTS_BCMATCH = 0x128,
    RADIO_EVENTS_CRCOK = 0x130,
    RADIO_EVENTS_CRCERROR = 0x134,
};

NRF52_PERIPHERAL(RADIO, radio)

typedef void (*radio_tx_cb_t)(void *userdata, uint8_t *data, size_t len);

void radio_set_tx_cb(RADIO_t *, radio_tx_cb_t cb, void *userdata);
