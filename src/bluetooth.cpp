#include "ansi_colors.h"
#include "bluetooth.h"
#include "bluetooth/ble_packets.hpp"

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

    uint64_t cur_cycles = nrf52832_get_cycle_counter(bt->nrf);
    if (cur_cycles - bt->last_conn_event_cycles >= (ConnIntervalMS * NRF52832_HFCLK_FREQUENCY) / 1000)
    {
        bt->last_conn_event_cycles = cur_cycles;

        if (bt->pending_packets.empty())
        {
            if (bt->connected)
            {
                auto packet = BLE::Data::Packet::CreateEmpty(*bt);
                BLE::Packet *p = packet.get();
                bt->Send(*p);
            }
        }
        else
        {
            auto &packet = bt->pending_packets.front();
            printf(BBLU "Sending packet: %s\n" CRESET, packet->name().c_str());
            bt->Send(*packet);
            bt->pending_packets.pop();
        }
    }

    while (event_queue_poll(bt->ev_queue, &ev, &data))
    {
        switch (ev)
        {
        case EVENT_RADIO_MESSAGE:
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
