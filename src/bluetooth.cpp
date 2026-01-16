#include "ansi_colors.h"
#include "bluetooth.h"
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
    event_type_t ev;
    void *data;

    if (bt->connected && !bt->exchanged_mtu && nrf52832_get_cycle_counter(bt->nrf) / NRF52832_HFCLK_FREQUENCY > 1)
    {
        auto packet = std::make_unique<BLE::ATT::EXCHANGE_MTU_REQ>();
        packet->ClientRxMTU = WantATT_MTU;
        auto le_packet = BLE::ATT::Packet::Create(std::move(packet), *bt);
        bt->Enqueue(std::move(le_packet));
        bt->exchanged_mtu = true;
    }

    while (event_queue_poll(bt->ev_queue, &ev, &data))
    {
        switch (ev)
        {
        case EVENT_RADIO_MESSAGE:
        {
            auto message = static_cast<event_radio_message_t *>(data);

            printf(MAG "RX ");
            print_hex(std::vector<uint8_t>(message->data, message->data + message->len));

            BinaryBuffer buffer(message->data, message->len - 3); // Ignore the 3 CRC bytes at the end
            BLE::LL::UncodedPacket packet;
            packet.deserialize(buffer);
            printf(BMAG "Received packet: %s\n" CRESET, packet.name().c_str());
            packet.run(*bt);
            break;
        }

        case EVENT_RADIO_RECEIVING:
        {
            if (!bt->pending_packets.empty())
            {
                auto &packet = bt->pending_packets.front();
                printf(BBLU "Sending packet: %s\n" CRESET, packet->name().c_str());
                bt->Send(*packet);
                bt->pending_packets.pop();
            }
            else if (bt->connected)
            {
                auto packet = BLE::Data::Packet::CreateEmpty(*bt);
                BLE::Packet *p = packet.get();
                bt->Send(*p);
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

void bluetooth_t::Send(const BLE::Packet &packet)
{
    BinaryBuffer buffer;
    packet.serialize(buffer);
    buffer.write(FakeCRC);

    printf(BLU "TX ");
    print_hex(buffer.get_data());

    radio_inject_packet(radio, buffer.get_data().data(), buffer.get_data().size());
}

void bluetooth_t::Enqueue(std::unique_ptr<BLE::Packet> packet)
{
    pending_packets.push(std::move(packet));
}
