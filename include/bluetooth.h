#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include "pinetime.h"
#include "peripherals/nrf52832/radio.h"

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
namespace BLE {
    class Packet;
};

#include <array>
#include <memory>
#include <queue>

constexpr uint32_t ConnIntervalMS = 600;
constexpr uint32_t ConnPeripheralLatency = 1;
constexpr uint32_t TransmitWindowSizeMS = 10; // Must be at most 10
constexpr uint32_t ConnSupervisionTimeoutMS = (1 + ConnPeripheralLatency) * ConnIntervalMS * 2 + 100;
constexpr std::array<uint8_t, 3> FakeCRC = { 0xFF, 0xFF, 0xFF };

struct bluetooth_t
{
    RADIO_t *radio;
    event_queue_t *ev_queue;
    NRF52832_t *nrf;
    bool connected = false;

    uint64_t last_conn_event_cycles = 0;

    unsigned int transmitSeqNum : 1;
    unsigned int nextExpectedSeqNum : 1;

    std::queue<std::unique_ptr<BLE::Packet>> pending_packets;

    bluetooth_t(pinetime_t *pt) : radio(static_cast<RADIO_t *>(nrf52832_get_peripheral(pinetime_get_nrf52832(pt), INSTANCE_RADIO))),
                                  ev_queue(pinetime_get_event_queue(pt)),
                                  nrf(pinetime_get_nrf52832(pt))
    {
    }

    void Send(const BLE::Packet &packet);

    void Enqueue(std::unique_ptr<BLE::Packet> packet);
};

extern "C"
{
#else
typedef struct bluetooth_t bluetooth_t;
#endif

    bluetooth_t *bluetooth_new(pinetime_t *pt);
    void bluetooth_run(bluetooth_t *);

#ifdef __cplusplus
}
#endif
