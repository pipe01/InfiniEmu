#pragma once

#include <assert.h>
#include <stdint.h>

#include <capstone/capstone.h>

uint32_t AddWithCarry(uint32_t x, uint32_t y, bool *carry, bool *overflow) {
    uint64_t unsigned_sum = (uint64_t)x + (uint64_t)y + (uint64_t)*carry;
    int64_t signed_sum = (int64_t)x + (int64_t)y + (int64_t)*carry;

    uint32_t result = unsigned_sum & 0xFFFFFFFF;
    assert(result == (signed_sum & 0xFFFFFFFF));

    *carry = result != unsigned_sum;
    *overflow = (signed_sum & 0xFFFFFFFF) != (int64_t)result;

    return result;
}

uint32_t Shift_C(uint32_t value, arm_shifter type, uint32_t amount, bool *carry)
{
    assert(!(type == ARM_SFT_RRX && amount != 1));

    if (amount == 0)
        return value;

    switch (type)
    {
    case ARM_SFT_LSL:
        *carry = (value >> (32 - amount)) & 1;
        return value << amount;

    case ARM_SFT_LSR:
        *carry = (value >> (amount - 1)) & 1;
        return value >> amount;

    case ARM_SFT_ASR:
        *carry = (value >> (amount - 1)) & 1;
        return (int32_t)value >> amount;

    case ARM_SFT_ROR:
        *carry = (value >> (amount - 1)) & 1;
        return (value >> amount) | (value << (32 - amount));

    case ARM_SFT_RRX:
        //TODO: Implement

    default:
        fprintf(stderr, "Unhandled shift type %d\n", type);
        abort();
    }
}

bool UnsignedSatQ(int32_t i, uint32_t n, uint32_t *result)
{
    if (i > (2 << n) - 1)
    {
        *result = (2 << n) - 1;
        return true;
    }
    else if (i < 0)
    {
        *result = 0;
        return true;
    }
    else
    {
        *result = i;
        return false;
    }
}