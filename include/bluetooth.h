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
namespace BLE
{
    class Packet;
};

#include <array>
#include <memory>
#include <queue>

constexpr uint32_t ConnIntervalMS = 100;
constexpr uint32_t ConnPeripheralLatency = 0;
constexpr uint32_t TransmitWindowSizeMS = 10; // Must be at most 10
constexpr uint32_t ConnSupervisionTimeoutMS = (1 + ConnPeripheralLatency) * ConnIntervalMS * 2 + 100;
constexpr std::array<uint8_t, 3> FakeCRC = {0xFF, 0xFF, 0xFF};

constexpr uint16_t WantATT_MTU = 247;

enum Stage
{
    NONE,
    CONNECTED,
    EXCHANGED_MTU,
    REQUESTED_INFO,
};

struct pending_packet_t
{
    uint64_t send_at;
    std::unique_ptr<BLE::Packet> packet;
};

class PendingCompare
{
public:
    bool operator()(pending_packet_t &a, pending_packet_t &b)
    {
        // Lower send_at should come first
        return a.send_at > b.send_at;
    }
};

struct bluetooth_t
{
    RADIO_t *radio;
    event_queue_t *ev_queue;
    NRF52832_t *nrf;
    bool connected = false;

    bool sent_req = false;
    Stage stage = NONE;
    uint16_t att_mtu = 23; // Default MTU

    struct
    {
        bool in_fragmented = false;
        uint32_t total_length;
        uint8_t channel;
        std::vector<uint8_t> buffer;
    } l2cap_frag;

    uint64_t last_conn_event_cycles = 0;

    unsigned int transmitSeqNum : 1;
    unsigned int nextExpectedSeqNum : 1;

    std::priority_queue<pending_packet_t, std::vector<pending_packet_t>, PendingCompare> pending_packets;

    bluetooth_t(pinetime_t *pt) : radio(static_cast<RADIO_t *>(nrf52832_get_peripheral(pinetime_get_nrf52832(pt), INSTANCE_RADIO))),
                                  ev_queue(pinetime_get_event_queue(pt)),
                                  nrf(pinetime_get_nrf52832(pt))
    {
    }

    void Send(const BLE::Packet &packet);

    void Enqueue(std::unique_ptr<BLE::Packet> packet, size_t delay_ms);
    void Enqueue(std::unique_ptr<BLE::Packet> packet)
    {
        Enqueue(std::move(packet), 0);
    }
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
