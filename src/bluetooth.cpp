#include "ansi_colors.h"
#include "bluetooth.hpp"
#include "bluetooth/ble_packets.hpp"

/**
 * Connection events timing:
 *  The events should happen every ConnIntervalMS millisecond, and the NimBLE stack sets up an RTC timer to enable RX correspondingly.
 *  However, it assumes that the radio peripheral will take some time to ramp up etc, which our emulator doesn't do and it would
 *    be hard to exactly replicate.
 *  Since it accounts for this by reducing the RTC timer's period, if the emulator were to start the events at exactly ConnIntervalMS
 *    it would slowly drift out of sync.
 *  Thus, we instead tell the radio peripheral to tell us when it has been instructed to start receiving, which allows us to send
 *    our messages only when it's ready to receive them without having to nail the timing.
 */

void print_hex(const std::vector<uint8_t> &data)
{
    printf("[%ld] ", data.size());

    for (auto byte : data)
    {
        printf("%02X", byte);

        if (&byte != &data.back())
            printf(" ");
    }
    printf(CRESET "\n");
}

extern "C" bluetooth_t *bluetooth_new(pinetime_t *pt)
{
    return new bluetooth_t(pt);
}

extern "C" void bluetooth_run(bluetooth_t *bt)
{
    bt->Run();
}

void bluetooth_t::Run()
{
    event_type_t ev;
    void *data;

    while (event_queue_poll(ev_queue, &ev, &data))
    {
        switch (ev)
        {
        case EVENT_RADIO_MESSAGE:
        {
            auto message = static_cast<event_radio_message_t *>(data);

#if ENABLE_BLE_LOG
            printf(MAG "RX ");
            print_hex(std::vector<uint8_t>(message->data, message->data + message->len));
#endif

            BinaryBuffer buffer(message->data, message->len - 4); // Ignore the 3 CRC bytes at the end plus one byte that I can't figure out where it's coming from
            BLE::LL::UncodedPacket packet;
            packet.deserialize(*this, buffer);
            BLE_LOG(BMAG, "Received packet: %s\n", packet.name().c_str());
            packet.run(*this);

            if (read_request.has_value() && nrf52832_get_cycle_counter(nrf) >= read_request->timeout_at)
            {
                read_request->callback(-1, {});
                read_request.reset();
            }

            break;
        }

        case EVENT_RADIO_RECEIVING:
        {
            if (pending_terminate_packet)
            {
                Send(*pending_terminate_packet.get());
                Reset();
                break;
            }

            bool sent = false;
            if (!pending_packets.empty())
            {
                auto &packet = pending_packets.top();
                if (nrf52832_get_cycle_counter(nrf) >= packet.send_at)
                {
                    BLE_LOG(BBLU, "Sending packet: %s\n", packet.packet->name().c_str());
                    Send(*packet.packet);
                    pending_packets.pop();
                    sent = true;
                }
            }

            if (!sent && connected)
            {
                auto packet = BLE::Data::Packet::CreateEmpty(*this);
                BLE::Packet *p = packet.get();
                Send(*p);
            }
            break;
        }

        default:
            break;
        }

        if (data)
            free(data);
    }
}

void bluetooth_t::Connect()
{
    if (connected || !received_advertising)
        return;

    BLE::LL::Advertising::CONNECT_IND inner;
    inner.InitA = OurAddress;
    inner.AdvA = peripheral_adva;
    inner.AA = OurAccessAddress;
    inner.CRCInit = {0xBB, 0xBB, 0xBB};
    inner.WinSize = TransmitWindowSizeMS / 1.25;
    inner.WinOffset = 0;
    inner.Interval = ConnIntervalMS / 1.25;
    inner.Latency = ConnPeripheralLatency;
    inner.Timeout = ConnSupervisionTimeoutMS / 10;
    inner.ChM = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
    inner.Hop_SCA = 7; // Hop=7, SCA=0

    Enqueue(BLE::LL::Advertising::Packet::Create(inner));
    connected = true;
    stage = CONNECTED;
    last_conn_event_cycles = nrf52832_get_cycle_counter(nrf);
}

void bluetooth_t::Disconnect()
{
    BLE::Data::Control inner;
    inner.Opcode = BLE::Data::LL_TERMINATE_IND;
    inner.Params = {0x13}; // Remote User Terminated Connection

    pending_terminate_packet = BLE::Data::Packet::Create(inner, *this);
}

void bluetooth_t::Send(const BLE::Packet &packet)
{
    BinaryBuffer buffer;
    packet.serialize(*this, buffer);
    buffer.write(FakeCRC);

#if ENABLE_BLE_LOG
    printf(BLU "TX ");
    print_hex(buffer.get_data());
#endif

    radio_inject_packet(radio, buffer.get_data().data(), buffer.get_data().size());
}

void bluetooth_t::Enqueue(std::unique_ptr<BLE::Packet> packet, size_t delay_ms)
{
    pending_packet_t pend{};
    pend.packet = std::move(packet);

    if (delay_ms > 0)
        pend.send_at = nrf52832_get_cycle_counter(nrf) + (delay_ms * NRF52832_HFCLK_FREQUENCY) / 1000;

    pending_packets.push(std::move(pend));
}

void bluetooth_t::Enqueue(std::unique_ptr<BLE::Packet> packet)
{
    Enqueue(std::move(packet), 0);
}

bool bluetooth_t::EnqueueReadRequest(uint16_t handle, read_callback callback, size_t timeout_msec)
{
    if (!IsReady())
        return false;

    read_request = (read_request_t){
        .timeout_at = nrf52832_get_cycle_counter(nrf) + (timeout_msec * NRF52832_HFCLK_FREQUENCY) / 1000,
        .callback = callback,
    };

    auto packet = std::make_unique<BLE::ATT::READ_REQ>();
    packet->Handle = handle;
    auto le_packet = BLE::ATT::Packet::Create(std::move(packet), *this);
    Enqueue(std::move(le_packet));

    return true;
}

void bluetooth_t::Reset()
{
    connected = false;
    received_advertising = false;
    sent_req = false;
    stage = NONE;
    att_mtu = 23;
    l2cap_frag = {};
    read_request.reset();
    last_conn_event_cycles = 0;
    transmitSeqNum = 1;
    nextExpectedSeqNum = 1;
    attrs16.clear();
    attrs128.clear();
    pending_terminate_packet.reset();
    pending_packets = {};
}
