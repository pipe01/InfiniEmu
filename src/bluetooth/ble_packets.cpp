#include "ansi_colors.h"
#include "bluetooth/ble_packets.hpp"

void BLE::LL::UncodedPacket::deserialize(bluetooth_t &bt, BinaryBuffer &buffer)
{
    buffer.fill(access_address);

    if (access_address == AdvertisingAccessAddress)
        pdu = std::make_unique<Advertising::Packet>();
    else
        pdu = std::make_unique<Data::Packet>();
    pdu->deserialize(bt, buffer);
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
    bt.peripheral_adva = AdvA;
    bt.received_advertising = true;
}

void BLE::Data::Packet::run(bluetooth_t &bt)
{
    if (Header.SN == bt.nextExpectedSeqNum)
    {
        bt.nextExpectedSeqNum++;
    }
    else
    {
        BLE_LOG(BYEL, "Packet with invalid SN received\n");
        return;
    }

    if (Header.NESN == bt.transmitSeqNum)
    {
        BLE_LOG(BYEL, "Last packet not acknowledged\n");
    }
    else
    {
        bt.transmitSeqNum++;
    }

    if (PDU) // PDU may be null on empty packets
    {
        PDU->run(bt);
    }
    else if (!bt.sent_req)
    {
        bt.sent_req = true;

        switch (bt.stage)
        {
        case NONE:
            break;

        case CONNECTED:
        {
            auto packet = std::make_unique<BLE::ATT::EXCHANGE_MTU_REQ>();
            packet->ClientRxMTU = WantATT_MTU;
            auto le_packet = BLE::ATT::Packet::Create(std::move(packet), bt);
            bt.Enqueue(std::move(le_packet));
            break;
        }

        case EXCHANGED_MTU:
        {
            auto packet = std::make_unique<BLE::ATT::FIND_INFORMATION_REQ>();
            packet->StartingHandle = 1;
            packet->EndingHandle = 0xFFFF;
            auto le_packet = BLE::ATT::Packet::Create(std::move(packet), bt);
            bt.Enqueue(std::move(le_packet), 1000);
            break;
        }

        case DONE:
        {
            uint16_t handle = 0;
            for (auto p = bt.attrs16.begin(); p != bt.attrs16.end(); ++p)
            {
                if (p->second == 0x2803)
                {
                    handle = p->first;
                    break;
                }
            }

            auto packet = std::make_unique<BLE::ATT::READ_REQ>();
            packet->Handle = handle;
            auto le_packet = BLE::ATT::Packet::Create(std::move(packet), bt);
            bt.Enqueue(std::move(le_packet));
            break;
        }
        }
    }
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
    BLE_LOG(GRN, "Attribute %d value updated to %s\n", Handle, ShowHex(Value).c_str());
}

void BLE::ATT::EXCHANGE_MTU_RSP::run(bluetooth_t &bt)
{
    bt.att_mtu = std::min(WantATT_MTU, ServerRxMTU);
    bt.sent_req = false;
    bt.stage = EXCHANGED_MTU;
}

void BLE::ATT::ERROR_RSP::run(bluetooth_t &bt)
{
    if (bt.read_request.has_value())
    {
        bt.read_request->callback(ErrorCode, {});
        bt.read_request.reset();
    }
    else
    {
        abort();
    }
}

void BLE::ATT::FIND_INFORMATION_RSP::run(bluetooth_t &bt)
{
    if (Format == 1)
    {
        // 16-bit UUIDs
        size_t handle_count = InformationData.size() / 4;
        BinaryBuffer buffer(InformationData);

        uint16_t last_handle = 0xFFFF;
        for (size_t i = 0; i < handle_count; i++)
        {
            uint16_t handle = buffer.u16();
            uint16_t uuid = buffer.u16();

            bt.attrs16[handle] = uuid;

            BLE_LOG(BCYN, "Discovered handle %d, UUID: 0x%X\n", handle, uuid);
            last_handle = handle;
        }

        // Send again to discover 128-bit UUID handles
        auto packet = std::make_unique<BLE::ATT::FIND_INFORMATION_REQ>();
        packet->StartingHandle = last_handle + 1;
        packet->EndingHandle = 0xFFFF;
        auto le_packet = BLE::ATT::Packet::Create(std::move(packet), bt);
        bt.Enqueue(std::move(le_packet));
    }
    else if (Format == 2)
    {
        // 128-bit UUIDs

        size_t handle_count = InformationData.size() / 18;
        BinaryBuffer buffer(InformationData);

        std::array<uint8_t, 128 / 8> uuid;
        for (size_t i = 0; i < handle_count; i++)
        {
            uint16_t handle = buffer.u16();
            buffer.fill(uuid);

            bt.attrs128[handle] = uuid;

#if ENABLE_BLE_LOG
            printf(BCYN "Discovered handle %d, UUID: ", handle);
            for (auto it = uuid.rbegin(); it != uuid.rend(); ++it)
            {
                printf("%02X", *it);
            }
            printf("\n" CRESET);
#endif
        }

        bt.sent_req = false;
        bt.stage = DONE;
    }
    else
    {
        abort();
    }
}

void BLE::ATT::READ_RSP::run(bluetooth_t &bt)
{
    BLE_LOG(GRN, "Read Response: %s\n", ShowHex(Value).c_str());

    if (bt.read_request.has_value())
    {
        bt.read_request->callback(0, std::move(Value));
        bt.read_request.reset();
    }
}
