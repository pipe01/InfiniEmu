#pragma once

#include <array>
#include <vector>
#include <memory>
#include <string>
#include <format>
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

        virtual void serialize(BinaryBuffer &buffer) const = 0;
        virtual void deserialize(BinaryBuffer &buffer) = 0;

        virtual void run(bluetooth_t &bt)
        {
            assert(false);
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

            void serialize(BinaryBuffer &buffer) const override
            {
                buffer.write(access_address);
                pdu->serialize(buffer);
            }

            void deserialize(BinaryBuffer &buffer) override;

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

                void serialize(BinaryBuffer &buffer) const override
                {
                    buffer.write(AdvA);
                    buffer.write(AdvData);
                }

                void deserialize(BinaryBuffer &buffer) override
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

                void serialize(BinaryBuffer &buffer) const override
                {
                    buffer.write(Scan);
                    buffer.write(AdvA);
                }

                void deserialize(BinaryBuffer &buffer) override
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

                void serialize(BinaryBuffer &buffer) const override
                {
                    buffer.write(AdvA);
                    buffer.write(ScanRspData);
                }

                void deserialize(BinaryBuffer &buffer) override
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

                void serialize(BinaryBuffer &buffer) const override
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

                void deserialize(BinaryBuffer &buffer) override
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

                void serialize(BinaryBuffer &buffer) const override
                {
                    auto hdr = Header;
                    hdr.Length = PDU ? PDU->size() : 0;

                    buffer.write(hdr);
                    PDU->serialize(buffer);
                }

                void deserialize(BinaryBuffer &buffer) override
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
                    PDU->deserialize(buffer);
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
        struct Packet : public BLE::Packet
        {
            NAME("LL::L2CAP::ATT::Packet")

            struct
            {
                unsigned int Method : 6;
                unsigned int Command : 1;
                unsigned int AuthSignature : 1;
            } __attribute__((packed)) Header;
            static_assert(sizeof(Header) == 1);

            any_bytes Parameters;

            size_t size() override
            {
                return 1 + Parameters.size();
            }

            void serialize(BinaryBuffer &buffer) const override
            {
                buffer.write(Header);
                buffer.write(Parameters);
            }

            void deserialize(BinaryBuffer &buffer) override
            {
                buffer.read(Header);
                buffer.fill_remaining(Parameters);
            }
        };
    };

    namespace L2CAP
    {
        struct Packet : public BLE::Packet
        {
            NAME_PARENT("LL::L2CAP::Packet", PDU)

            uint16_t PDULength;
            uint16_t Channel;

            child PDU;

            uint8_t LLID() const
            {
                return 2;
            }

            size_t size() override
            {
                return 4 + (PDU ? PDU->size() : 0);
            }

            void serialize(BinaryBuffer &buffer) const override
            {
                buffer.write(PDU->size());
                buffer.write(Channel);
                PDU->serialize(buffer);
            }

            void deserialize(BinaryBuffer &buffer) override
            {
                buffer.read(PDULength);
                buffer.read(Channel);
                switch (Channel)
                {
                case L2CAP_CHANNEL_ATT:
                    PDU = std::make_unique<ATT::Packet>();
                    break;

                default:
                    assert(false);
                    break;
                }
                PDU->deserialize(buffer);
            }

            void run(bluetooth_t &bt) override;
        };
    };

    namespace Data
    {
        constexpr byte LL_PERIPHERAL_FEATURE_REQ = 0x0E;
        constexpr byte LL_FEATURE_RSP = 0x09;
        constexpr byte LL_LENGTH_REQ = 0x14;
        constexpr byte LL_LENGTH_RSP = 0x15;

        struct Control : public Packet
        {
            NAME_FMT("LL::Data::Control {}", Opcode)

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

            void serialize(BinaryBuffer &buffer) const override
            {
                buffer.write(Opcode);
                buffer.write(Params);
            }

            void deserialize(BinaryBuffer &buffer) override
            {
                buffer.read(Opcode);
                buffer.fill_remaining(Params);
            }

            void run(bluetooth_t &bt) override;
        };

        struct Packet : public BLE::Packet
        {
            NAME_PARENT("LL::Data::Packet", PDU)

            struct
            {
                unsigned int LLID : 2;
                unsigned int NESN : 1;
                unsigned int SN : 1;
                unsigned int MD : 1;
                unsigned int CP : 1;
                unsigned int RFU : 1;
                unsigned int Length : 8;
            } __attribute__((packed)) Header;
            static_assert(sizeof(Header) == 2);

            child PDU;

            size_t size() override
            {
                return 2 + (PDU ? PDU->size() : 0);
            }

            void serialize(BinaryBuffer &buffer) const override
            {
                auto hdr = Header;
                hdr.Length = PDU ? PDU->size() : 0;

                buffer.write(hdr);
                if (PDU)
                    PDU->serialize(buffer);
            }

            void deserialize(BinaryBuffer &buffer) override
            {
                buffer.read(Header);
                if (Header.Length == 0)
                    return;

                switch (Header.LLID)
                {
                case 2: // First fragment
                case 1: // Remaining fragments
                    PDU = std::make_unique<L2CAP::Packet>();
                    break;

                case 3:
                    PDU = std::make_unique<Control>();
                    break;
                }
                if (PDU)
                    PDU->deserialize(buffer);
            }

            void run(bluetooth_t &bt) override;

            template <typename T>
            static std::unique_ptr<LL::UncodedPacket> Create(const T &inner_packet, bluetooth_t &bt)
            {
                auto packet = std::make_unique<LL::UncodedPacket>();
                packet->access_address = OurAccessAddress;

                auto data_packet = std::make_unique<Packet>();
                data_packet->Header.LLID = inner_packet.LLID();
                data_packet->Header.SN = bt.transmitSeqNum;
                data_packet->Header.NESN = bt.nextExpectedSeqNum;
                data_packet->PDU = std::make_unique<T>(inner_packet);

                packet->pdu = std::move(data_packet);
                return packet;
            }

            static std::unique_ptr<LL::UncodedPacket> CreateEmpty(bluetooth_t &bt)
            {
                auto packet = std::make_unique<LL::UncodedPacket>();
                packet->access_address = OurAccessAddress;

                auto data_packet = std::make_unique<Packet>();
                data_packet->Header.LLID = 3;
                data_packet->Header.SN = bt.transmitSeqNum;
                data_packet->Header.NESN = bt.nextExpectedSeqNum;
                data_packet->PDU = nullptr;

                packet->pdu = std::move(data_packet);
                return packet;
            }
        };
    };
};
