#pragma once

#include <array>
#include <vector>
#include <memory>
#include <string>
#include <format>
#include <type_traits>

#include <string.h>
#include <stdint.h>

#include "bluetooth.h"

using byte = uint8_t;
template <std::size_t N>
using bytes = std::array<byte, N>;
using any_bytes = std::vector<byte>;

constexpr bytes<4> AdvertisingAccessAddress = {0xd6, 0xbe, 0x89, 0x8e};
constexpr bytes<6> OurAddress = {0xde, 0xad, 0xbe, 0xef, 0x69, 0x69};
constexpr bytes<4> OurAccessAddress = {0xaa, 0xbb, 0xcc, 0xdd};

class BinaryBuffer
{
    std::vector<uint8_t> data;
    size_t position = 0;

public:
    BinaryBuffer() = default;
    BinaryBuffer(size_t size) : data(size) {}
    BinaryBuffer(const std::vector<uint8_t> &data) : data(data) {}
    BinaryBuffer(const uint8_t *data, size_t size) : data(data, data + size) {}

    const std::vector<uint8_t> &get_data() const
    {
        return data;
    }

    size_t get_position() { return position; }

    void write(uint8_t value)
    {
        data.push_back(value);
    }
    void write(uint16_t value)
    {
        data.push_back(value & 0xFF);
        data.push_back((value >> 8) & 0xFF);
    }
    template <auto N>
    void write(const bytes<N> data)
    {
        for (size_t i = 0; i < N; ++i)
            this->data.push_back(data[i]);
    }
    void write(const any_bytes data)
    {
        this->data.insert(this->data.end(), data.begin(), data.end());
    }
    template <typename T>
    void write(const T &value)
    {
        const uint8_t *data = reinterpret_cast<const uint8_t *>(&value);
        for (size_t i = 0; i < sizeof(T); ++i)
            this->data.push_back(data[i]);
    }

    template <auto N>
    void fill(bytes<N> &data)
    {
        for (size_t i = 0; i < N; ++i)
            data[i] = u8();
    }
    void fill(any_bytes &data, size_t size)
    {
        data.resize(size);
        for (size_t i = 0; i < size; ++i)
            data[i] = u8();
    }
    void fill_remaining(any_bytes &data)
    {
        size_t remaining = this->data.size() - position;
        fill(data, remaining);
    }

    template <typename T>
    void read(T &value)
    {
        memcpy(&value, &data[position], sizeof(T));
        position += sizeof(T);
    }

    uint8_t u8()
    {
        return data[position++];
    }
    uint16_t u16()
    {
        uint16_t value = data[position] | (data[position + 1] << 8);
        position += 2;
        return value;
    }
};

static inline std::string ShowHex(any_bytes b)
{
    std::string result;
    result.reserve(b.size() * 5);

    for (size_t i = 0; i < b.size(); ++i)
    {
        result += std::format("0x{:02X}", b[i]);
        if (i + 1 < b.size())
            result += " ";
    }
    return result;
}

namespace BLE
{
#define NAME(n) \
    const std::string name() const override { return n; }
#define NAME_FMT(fmt, ...) \
    const std::string name() const override { return std::format(fmt, ##__VA_ARGS__); }
#define NAME_PARENT(n, m) \
    const std::string name() const override { return (m ? m->name() : "Empty") + " > " n; }

    constexpr uint32_t L2CAP_CHANNEL_ATT = 0x04;

    struct Packet
    {
        virtual size_t size() = 0;
        virtual const std::string name() const = 0;

        virtual void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const = 0;
        virtual void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) = 0;

        virtual void run(bluetooth_t &bt)
        {
            abort();
        }
    };

    using child = std::unique_ptr<Packet>;

    template <uint8_t T>
    struct PDU : public BLE::Packet
    {
        static constexpr uint8_t Type = T;
    };

    namespace LL
    {
        struct UncodedPacket : public Packet
        {
            NAME_PARENT("LL::UncodedPacket", pdu)

            bytes<4> access_address;
            child pdu;

            size_t size() override
            {
                return 4 + (pdu ? pdu->size() : 0);
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(access_address);
                pdu->serialize(bt, buffer);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override;

            void run(bluetooth_t &bt) override;
        };

        namespace Advertising
        {
            struct ADV_IND : public PDU<0b0000>
            {
                NAME("LL::Advertising::ADV_IND")

                bytes<6> AdvA;
                any_bytes AdvData;

                size_t size() override
                {
                    return 6 + AdvData.size();
                }

                void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
                {
                    buffer.write(AdvA);
                    buffer.write(AdvData);
                }

                void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
                {
                    buffer.fill(AdvA);
                    buffer.fill_remaining(AdvData);
                }

                void run(bluetooth_t &bt) override;
            };

            struct SCAN_REQ : public PDU<0b0011>
            {
                NAME("LL::Advertising::SCAN_REQ")

                bytes<6> Scan;
                bytes<6> AdvA;

                size_t size() override
                {
                    return 12;
                }

                void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
                {
                    buffer.write(Scan);
                    buffer.write(AdvA);
                }

                void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
                {
                    buffer.fill(Scan);
                    buffer.fill(AdvA);
                }
            };

            struct SCAN_RSP : public PDU<0b0100>
            {
                NAME("LL::Advertising::SCAN_RSP")

                bytes<6> AdvA;
                any_bytes ScanRspData;

                size_t size() override
                {
                    return 6 + ScanRspData.size();
                }

                void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
                {
                    buffer.write(AdvA);
                    buffer.write(ScanRspData);
                }

                void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
                {
                    buffer.fill(AdvA);
                    buffer.fill_remaining(ScanRspData);
                }
            };

            struct CONNECT_IND : public PDU<0b0101>
            {
                NAME("LL::Advertising::CONNECT_IND")

                bytes<6> InitA;
                bytes<6> AdvA;
                bytes<4> AA;
                bytes<3> CRCInit;
                byte WinSize;
                uint16_t WinOffset;
                uint16_t Interval;
                uint16_t Latency;
                uint16_t Timeout;
                bytes<5> ChM;
                byte Hop_SCA;

                size_t size() override
                {
                    return 34;
                }

                void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
                {
                    buffer.write(InitA);
                    buffer.write(AdvA);
                    buffer.write(AA);
                    buffer.write(CRCInit);
                    buffer.write(WinSize);
                    buffer.write(WinOffset);
                    buffer.write(Interval);
                    buffer.write(Latency);
                    buffer.write(Timeout);
                    buffer.write(ChM);
                    buffer.write(Hop_SCA);
                }

                void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
                {
                    buffer.fill(InitA);
                    buffer.fill(AdvA);
                    buffer.fill(AA);
                    buffer.fill(CRCInit);
                    buffer.read(WinSize);
                    buffer.read(WinOffset);
                    buffer.read(Interval);
                    buffer.read(Latency);
                    buffer.read(Timeout);
                    buffer.fill(ChM);
                    buffer.read(Hop_SCA);
                }
            };

            struct Packet : public BLE::Packet
            {
                NAME_PARENT("LL::Advertising::Packet", PDU)

                struct
                {
                    unsigned int PDUType : 4;
                    unsigned int RFU : 1;
                    unsigned int ChSel : 1;
                    unsigned int TxAdd : 1;
                    unsigned int RxAdd : 1;
                    unsigned int Length : 8;
                } __attribute__((packed)) Header;
                static_assert(sizeof(Header) == 2);

                child PDU;

                size_t size() override
                {
                    return 2 + (PDU ? PDU->size() : 0);
                }

                void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
                {
                    auto hdr = Header;
                    hdr.Length = PDU ? PDU->size() : 0;

                    buffer.write(hdr);
                    PDU->serialize(bt, buffer);
                }

                void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
                {
                    buffer.read(Header);
                    switch (Header.PDUType)
                    {
                    case ADV_IND::Type:
                        PDU = std::make_unique<ADV_IND>();
                        break;
                    case SCAN_REQ::Type:
                        PDU = std::make_unique<SCAN_REQ>();
                        break;
                    case SCAN_RSP::Type:
                        PDU = std::make_unique<SCAN_RSP>();
                        break;
                    case CONNECT_IND::Type:
                        PDU = std::make_unique<CONNECT_IND>();
                        break;
                    default:
                        // Unknown PDU type
                        PDU = nullptr;
                        return;
                    }
                    PDU->deserialize(bt, buffer);
                }

                void run(bluetooth_t &bt) override;

                template <typename T>
                static std::unique_ptr<UncodedPacket> Create(const T &inner_packet)
                {
                    auto packet = std::make_unique<UncodedPacket>();
                    packet->access_address = AdvertisingAccessAddress;

                    auto adv_packet = std::make_unique<BLE::LL::Advertising::Packet>();
                    adv_packet->Header.PDUType = T::Type;
                    adv_packet->PDU = std::make_unique<T>(inner_packet);

                    packet->pdu = std::move(adv_packet);
                    return packet;
                }
            };
        };

    };

    namespace ATT
    {
        struct ERROR_RSP : public BLE::Packet
        {
            NAME("ATT::ERROR_RSP")

            static constexpr uint32_t Method = 0x01;

            uint8_t ReqOpcode;
            uint16_t Handle;
            uint8_t ErrorCode;

            size_t size() override
            {
                return 4;
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(ReqOpcode);
                buffer.write(Handle);
                buffer.write(ErrorCode);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(ReqOpcode);
                buffer.read(Handle);
                buffer.read(ErrorCode);
            }

            void run(bluetooth_t &bt) override;
        };

        struct EXCHANGE_MTU_REQ : public BLE::Packet
        {
            NAME("ATT::EXCHANGE_MTU_REQ")

            static constexpr uint32_t Method = 0x02;

            uint16_t ClientRxMTU;

            size_t size() override
            {
                return 2;
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(ClientRxMTU);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(ClientRxMTU);
            }
        };

        struct EXCHANGE_MTU_RSP : public BLE::Packet
        {
            NAME("ATT::EXCHANGE_MTU_RSP")

            static constexpr uint32_t Method = 0x03;

            uint16_t ServerRxMTU;

            size_t size() override
            {
                return 2;
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(ServerRxMTU);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(ServerRxMTU);
            }

            void run(bluetooth_t &bt) override;
        };

        struct FIND_INFORMATION_REQ : public BLE::Packet
        {
            NAME("ATT::FIND_INFORMATION_REQ")

            static constexpr uint32_t Method = 0x04;

            uint16_t StartingHandle;
            uint16_t EndingHandle;

            size_t size() override
            {
                return 4;
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(StartingHandle);
                buffer.write(EndingHandle);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(StartingHandle);
                buffer.read(EndingHandle);
            }
        };

        struct FIND_INFORMATION_RSP : public BLE::Packet
        {
            NAME("ATT::FIND_INFORMATION_RSP")

            static constexpr uint32_t Method = 0x05;

            uint8_t Format;
            any_bytes InformationData;

            size_t size() override
            {
                return 1 + InformationData.size();
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(Format);
                buffer.write(InformationData);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(Format);
                buffer.fill_remaining(InformationData);
            }

            void run(bluetooth_t &bt) override;
        };

        struct FIND_BY_TYPE_VALUE_REQ : public BLE::Packet
        {
            NAME("ATT::FIND_BY_TYPE_VALUE_REQ")

            static constexpr uint32_t Method = 0x06;

            uint16_t StartingHandle;
            uint16_t EndingHandle;
            uint16_t AttributeType;
            any_bytes AttributeValue;

            size_t size() override
            {
                return 6 + AttributeValue.size();
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(StartingHandle);
                buffer.write(EndingHandle);
                buffer.write(AttributeType);
                buffer.write(AttributeValue);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(StartingHandle);
                buffer.read(EndingHandle);
                buffer.read(AttributeType);
                buffer.fill_remaining(AttributeValue);
            }

            void run(bluetooth_t &bt) override;
        };

        struct HANDLE_VALUE_NTF : public BLE::Packet
        {
            NAME("ATT::HANDLE_VALUE_NTF")

            static constexpr uint32_t Method = 0x1B;

            uint16_t Handle;
            any_bytes Value;

            size_t size() override
            {
                return 2 + Value.size();
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(Handle);
                buffer.write(Value);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(Handle);
                buffer.fill_remaining(Value);
            }

            void run(bluetooth_t &bt) override;
        };

        struct Packet : public BLE::Packet
        {
            NAME_PARENT("ATT::Packet", Parameters)

            static constexpr uint32_t Channel = L2CAP_CHANNEL_ATT;

            struct
            {
                unsigned int Method : 6;
                unsigned int Command : 1;
                unsigned int AuthSignature : 1;
            } __attribute__((packed)) Header;
            static_assert(sizeof(Header) == 1);

            child Parameters;

            size_t size() override
            {
                return 1 + Parameters->size();
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(Header);
                Parameters->serialize(bt, buffer);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(Header);
                switch (Header.Method)
                {
                case ERROR_RSP::Method:
                    Parameters = std::make_unique<ERROR_RSP>();
                    break;
                case EXCHANGE_MTU_REQ::Method:
                    Parameters = std::make_unique<EXCHANGE_MTU_REQ>();
                    break;
                case EXCHANGE_MTU_RSP::Method:
                    Parameters = std::make_unique<EXCHANGE_MTU_RSP>();
                    break;
                case FIND_INFORMATION_REQ::Method:
                    Parameters = std::make_unique<FIND_INFORMATION_REQ>();
                    break;
                case FIND_INFORMATION_RSP::Method:
                    Parameters = std::make_unique<FIND_INFORMATION_RSP>();
                    break;
                case FIND_BY_TYPE_VALUE_REQ::Method:
                    Parameters = std::make_unique<FIND_BY_TYPE_VALUE_REQ>();
                    break;
                case HANDLE_VALUE_NTF::Method:
                    Parameters = std::make_unique<HANDLE_VALUE_NTF>();
                    break;

                default:
                    printf(BYEL "Unhandled ATT command 0x%X\n" CRESET, Header.Method);
                    break;
                }
                if (Parameters)
                    Parameters->deserialize(bt, buffer);
            }

            void run(bluetooth_t &bt) override;

            template <typename T>
            static std::unique_ptr<BLE::LL::UncodedPacket> Create(std::unique_ptr<T> inner_packet, bluetooth_t &bt);
        };
        static_assert(!std::is_abstract<Packet>());
    };

    namespace L2CAP
    {
        struct Packet : public BLE::Packet
        {
            NAME_PARENT("L2CAP::Packet", PDU)

            uint16_t PDULength;
            uint16_t Channel;

            bool is_first;

            // Packet() : is_first(true) {}
            Packet(bool is_first) : is_first(is_first)
            {
            }

            child PDU;

            uint8_t LLID() const
            {
                return 2;
            }

            size_t size() override
            {
                return 4 + (PDU ? PDU->size() : 0);
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write((uint16_t)PDU->size());
                buffer.write(Channel);
                PDU->serialize(bt, buffer);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                if (!bt.l2cap_frag.in_fragmented)
                {
                    buffer.read(PDULength);
                    buffer.read(Channel);

                    if (PDULength > buffer.get_data().size() - buffer.get_position() + (is_first ? 4 : 0))
                    {
                        assert(is_first);
                        // Start defragmentation
                        bt.l2cap_frag.in_fragmented = true;
                        bt.l2cap_frag.total_length = PDULength;
                        bt.l2cap_frag.channel = Channel;
                        bt.l2cap_frag.buffer.reserve(PDULength);
                        bt.l2cap_frag.buffer.insert(bt.l2cap_frag.buffer.begin(), buffer.get_data().begin() + buffer.get_position(), buffer.get_data().end());
                    }
                    else
                    {
                        deserialize_inner(bt, buffer);
                    }
                }
                else
                {
                    assert(!is_first);
                    bt.l2cap_frag.buffer.insert(bt.l2cap_frag.buffer.end(), buffer.get_data().begin() + buffer.get_position(), buffer.get_data().end());

                    if (bt.l2cap_frag.buffer.size() == bt.l2cap_frag.total_length)
                    {
                        // Received complete packet

                        PDULength = bt.l2cap_frag.total_length;
                        Channel = bt.l2cap_frag.channel;

                        BinaryBuffer buffer(bt.l2cap_frag.buffer);
                        deserialize_inner(bt, buffer);

                        bt.l2cap_frag.buffer.resize(0);
                        bt.l2cap_frag.in_fragmented = false;
                    }
                }
            }

            void run(bluetooth_t &bt) override;

            template <typename T>
            static std::unique_ptr<BLE::LL::UncodedPacket> Create(std::unique_ptr<T> inner_packet, bluetooth_t &bt);

        private:
            void deserialize_inner(bluetooth_t &bt, BinaryBuffer &buffer)
            {
                switch (Channel)
                {
                case L2CAP_CHANNEL_ATT:
                    PDU = std::make_unique<ATT::Packet>();
                    break;

                default:
                    abort();
                }
                PDU->deserialize(bt, buffer);
            }
        };
        static_assert(!std::is_abstract<Packet>());
    };

    namespace Data
    {
        constexpr byte LL_PERIPHERAL_FEATURE_REQ = 0x0E;
        constexpr byte LL_UNKNOWN_RSP = 0x07;
        constexpr byte LL_FEATURE_RSP = 0x09;
        constexpr byte LL_LENGTH_REQ = 0x14;
        constexpr byte LL_LENGTH_RSP = 0x15;

        struct Control : public Packet
        {
            NAME_FMT("Data::Control {}", Opcode)

            byte Opcode;
            any_bytes Params;

            uint8_t LLID() const
            {
                return 3;
            }

            size_t size() override
            {
                return 1 + Params.size();
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                buffer.write(Opcode);
                buffer.write(Params);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(Opcode);
                buffer.fill_remaining(Params);
            }

            void run(bluetooth_t &bt) override;
        };

        struct Packet : public BLE::Packet
        {
            NAME_PARENT("Data::Packet", PDU)

            struct
            {
                unsigned int LLID : 2;
                unsigned int NESN : 1;
                unsigned int SN : 1;
                unsigned int MD : 1;
                unsigned int CP : 1;
                unsigned int : 2;
                unsigned int Length : 8;
            } __attribute__((packed)) Header;
            static_assert(sizeof(Header) == 2);

            child PDU;

            size_t size() override
            {
                return 2 + (PDU ? PDU->size() : 0);
            }

            void serialize(bluetooth_t &bt, BinaryBuffer &buffer) const override
            {
                auto hdr = Header;
                hdr.Length = PDU ? PDU->size() : 0;
                hdr.SN = bt.transmitSeqNum;
                hdr.NESN = bt.nextExpectedSeqNum;

                buffer.write(hdr);
                if (PDU)
                    PDU->serialize(bt, buffer);
            }

            void deserialize(bluetooth_t &bt, BinaryBuffer &buffer) override
            {
                buffer.read(Header);
                if (Header.Length == 0)
                    return;

                assert(!Header.CP);

                switch (Header.LLID)
                {
                case 2: // First fragment
                    PDU = std::make_unique<L2CAP::Packet>(true);
                    break;

                case 1: // Remaining fragments
                    PDU = std::make_unique<L2CAP::Packet>(false);
                    break;

                case 3:
                    PDU = std::make_unique<Control>();
                    break;
                }
                if (PDU)
                    PDU->deserialize(bt, buffer);
            }

            void run(bluetooth_t &bt) override;

            template <typename T>
            static std::unique_ptr<LL::UncodedPacket> Create(const T &inner_packet, bluetooth_t &bt)
            {
                return Create(std::make_unique<T>(inner_packet), bt);
            }

            template <typename T>
            static std::unique_ptr<LL::UncodedPacket> Create(std::unique_ptr<T> inner_packet, bluetooth_t &bt)
            {
                auto packet = std::make_unique<LL::UncodedPacket>();
                packet->access_address = OurAccessAddress;

                auto data_packet = std::make_unique<Packet>();
                data_packet->Header.LLID = inner_packet->LLID();
                data_packet->PDU = std::move(inner_packet);

                packet->pdu = std::move(data_packet);
                return packet;
            }

            static std::unique_ptr<LL::UncodedPacket> CreateEmpty(bluetooth_t &bt)
            {
                auto packet = std::make_unique<LL::UncodedPacket>();
                packet->access_address = OurAccessAddress;

                auto data_packet = std::make_unique<Packet>();
                data_packet->Header.LLID = 1;
                data_packet->Header.SN = bt.transmitSeqNum;
                data_packet->Header.NESN = bt.nextExpectedSeqNum;
                data_packet->PDU = nullptr;

                packet->pdu = std::move(data_packet);
                return packet;
            }
        };
    };
};

template <typename T>
inline std::unique_ptr<BLE::LL::UncodedPacket> BLE::L2CAP::Packet::Create(std::unique_ptr<T> inner_packet, bluetooth_t &bt)
{
    auto packet = std::make_unique<Packet>(true);
    packet->Channel = T::Channel;
    packet->PDU = std::move(inner_packet);

    return Data::Packet::Create(std::move(packet), bt);
}

template <typename T>
inline std::unique_ptr<BLE::LL::UncodedPacket> BLE::ATT::Packet::Create(std::unique_ptr<T> inner_packet, bluetooth_t &bt)
{
    auto packet = std::make_unique<Packet>();
    packet->Header.Method = T::Method;
    packet->Parameters = std::move(inner_packet);

    return L2CAP::Packet::Create(std::move(packet), bt);
}
