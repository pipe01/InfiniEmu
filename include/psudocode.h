#pragma once

#include <stdint.h>

uint32_t AddWithCarry(uint32_t x, uint32_t y, bool *carry, bool *overflow) {
    uint64_t unsigned_sum = (uint64_t)x + (uint64_t)y + (uint64_t)*carry;
    int64_t signed_sum = (int64_t)x + (int64_t)y + (uint64_t)*carry;

    uint32_t result = unsigned_sum & 0xFFFFFFFF;

    *carry = (unsigned_sum >> 32) != 0;
    *overflow = (signed_sum & 0xFFFFFFFF) != (int64_t)result;

    return result;
}
