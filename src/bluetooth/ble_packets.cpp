#include "ansi_colors.h"
#include "bluetooth/ble_packets.hpp"

void BLE::LL::UncodedPacket::deserialize(BinaryBuffer &buffer)
{
    buffer.fill(access_address);

    if (access_address == AdvertisingAccessAddress)
        pdu = std::make_unique<Advertising::Packet>();
    else
        pdu = std::make_unique<Data::Packet>();
    pdu->deserialize(buffer);
}

void BLE::LL::UncodedPacket::run(bluetooth_t &bt)
{
    assert(pdu);
    pdu->run(bt);
}

void BLE::LL::Advertising::Packet::run(bluetooth_t &bt)
{
    assert(PDU);
    PDU->run(bt);
}

void BLE::LL::Advertising::ADV_IND::run(bluetooth_t &bt)
{
    CONNECT_IND inner;
    inner.InitA = OurAddress;
    inner.AdvA = AdvA;
    inner.AA = OurAccessAddress;
    inner.CRCInit = {0xBB, 0xBB, 0xBB};
    inner.WinSize = TransmitWindowSizeMS / 1.25;
    inner.WinOffset = 0;
    inner.Interval = ConnIntervalMS / 1.25;
    inner.Latency = ConnPeripheralLatency;
    inner.Timeout = ConnSupervisionTimeoutMS / 10;
    inner.ChM = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
    inner.Hop_SCA = 7; // Hop=7, SCA=0

    bt.Enqueue(Advertising::Packet::Create(inner));
    bt.connected = true;
}

void BLE::Data::Packet::run(bluetooth_t &bt)
{
    if (Header.SN == bt.nextExpectedSeqNum)
    {
        bt.nextExpectedSeqNum++;
    }
    else
    {
        printf(RED "Packet with invalid SN received\n" CRESET);
        return;
    }

    if (Header.NESN == bt.transmitSeqNum)
    {
        printf(RED "Last packet not acknowledged\n" CRESET);
    }
    else
    {
        bt.transmitSeqNum++;
    }

    if (PDU) // PDU may be null on empty packets
        PDU->run(bt);
}

void BLE::Data::Control::run(bluetooth_t &bt)
{
    switch (Opcode)
    {
    case LL_PERIPHERAL_FEATURE_REQ:
    {
        Control resp;
        resp.Opcode = LL_FEATURE_RSP;
        resp.Params.resize(8); // 8 zero bytes

        bt.Enqueue(Data::Packet::Create(resp, bt));
        break;
    }

    default:
        assert(false);
        break;
    }
}

void BLE::L2CAP::Packet::run(bluetooth_t &bt)
{
    assert(false);
}
