#pragma once

#include <array>
#include <format>
#include <type_traits>
#include <string>

#include <vector>
#include <string.h>
#include <stdint.h>

using byte = uint8_t;
template <std::size_t N>
using bytes = std::array<byte, N>;
using any_bytes = std::vector<byte>;

inline std::string ShowHex(any_bytes b)
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
    void write(const std::array<uint8_t, N> data)
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
