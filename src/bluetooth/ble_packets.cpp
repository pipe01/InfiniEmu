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
    bt.last_conn_event_cycles = nrf52832_get_cycle_counter(bt.nrf);
}

void BLE::Data::Packet::run(bluetooth_t &bt)
{
    if (Header.SN == bt.nextExpectedSeqNum)
    {
        bt.nextExpectedSeqNum++;
    }
    else
    {
        printf(BYEL "Packet with invalid SN received\n" CRESET);
        return;
    }

    if (Header.NESN == bt.transmitSeqNum)
    {
        printf(BYEL "Last packet not acknowledged\n" CRESET);
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
        abort();
    }
}

void BLE::L2CAP::Packet::run(bluetooth_t &bt)
{
    if (PDU)
        PDU->run(bt);
}

void BLE::ATT::Packet::run(bluetooth_t &bt)
{
    assert(Parameters);
    Parameters->run(bt);
}

void BLE::ATT::FIND_BY_TYPE_VALUE_REQ::run(bluetooth_t &bt)
{
    auto resp = std::make_unique<ERROR_RSP>();
    resp->ReqOpcode = Method;
    resp->Handle = StartingHandle;
    resp->ErrorCode = 0x0A;

    bt.Enqueue(ATT::Packet::Create(std::move(resp), bt));
}

void BLE::ATT::HANDLE_VALUE_NTF::run(bluetooth_t &bt)
{
    printf(GRN "Attribute %d value updated to %s\n", Handle, ShowHex(Value).c_str());
}

void BLE::ATT::EXCHANGE_MTU_RSP::run(bluetooth_t &bt)
{
    bt.att_mtu = std::min(WantATT_MTU, ServerRxMTU);
}