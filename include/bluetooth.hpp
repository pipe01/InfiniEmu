#pragma once

extern "C"
{
#include "pinetime.h"
#include "peripherals/nrf52832/radio.h"
}

#include "binary_buffer.hpp"

#include <array>
#include <memory>
#include <queue>
#include <map>
#include <string>
#include <optional>
#include <functional>

#if ENABLE_BLE_LOG
#define BLE_LOG(color, msg, ...) printf(color msg CRESET, ##__VA_ARGS__)
#else
#define BLE_LOG(...) do { } while(0)
#endif

constexpr uint32_t ConnIntervalMS = 100;
constexpr uint32_t ConnPeripheralLatency = 0;
constexpr uint32_t TransmitWindowSizeMS = 10; // Must be at most 10
constexpr uint32_t ConnSupervisionTimeoutMS = (1 + ConnPeripheralLatency) * ConnIntervalMS * 2 + 100;
constexpr std::array<uint8_t, 3> FakeCRC = {0xFF, 0xFF, 0xFF};

constexpr uint16_t WantATT_MTU = 247;

struct bluetooth_t;

namespace BLE
{
    class Packet
    {
    public:
        virtual size_t size() = 0;
        virtual const std::string name() const = 0;

        virtual void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const = 0;
        virtual void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) = 0;

        virtual void run(bluetooth_t &bt)
        {
            abort();
        }
    };
};

enum Stage
{
    NONE,
    CONNECTED,
    EXCHANGED_MTU,
    DONE,
};

struct pending_packet_t
{
    uint64_t send_at;
    std::unique_ptr<BLE::Packet> packet;
};

using read_callback = std::function<void(int error, any_bytes data)>;

struct read_request_t
{
    uint64_t timeout_at;
    read_callback callback;
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

    bytes<6UL> peripheral_adva;
    bool received_advertising;

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

    std::optional<read_request_t> read_request;

    uint64_t last_conn_event_cycles = 0;

    unsigned int transmitSeqNum : 1;
    unsigned int nextExpectedSeqNum : 1;

    std::map<uint16_t, uint16_t> attrs16;                      // handle -> uuid
    std::map<uint16_t, std::array<uint8_t, 128 / 8>> attrs128; // handle -> uuid

    std::unique_ptr<BLE::Packet> pending_terminate_packet;
    std::priority_queue<pending_packet_t, std::vector<pending_packet_t>, PendingCompare> pending_packets;

    bluetooth_t(pinetime_t *pt) : radio(static_cast<RADIO_t *>(nrf52832_get_peripheral(pinetime_get_nrf52832(pt), INSTANCE_RADIO))),
                                  ev_queue(pinetime_get_event_queue(pt)),
                                  nrf(pinetime_get_nrf52832(pt))
    {
    }

    void Run();

    void Connect();
    void Disconnect();

    void Enqueue(std::unique_ptr<BLE::Packet> packet, size_t delay_ms);
    void Enqueue(std::unique_ptr<BLE::Packet> packet);

    bool EnqueueReadRequest(uint16_t handle, read_callback callback, size_t timeout_msec);

    inline bool IsReady() { return stage == DONE && !read_request.has_value(); }

private:
    void Send(const BLE::Packet &packet);

    void Reset();
};

extern "C"
{
    bluetooth_t *bluetooth_new(pinetime_t *pt);
    void bluetooth_run(bluetooth_t *);
}
