#pragma once

#include <assert.h>
#include <stdint.h>

#include <capstone/capstone.h>

uint32_t AddWithCarry(uint32_t x, uint32_t y, bool *carry, bool *overflow)
{
    uint64_t unsigned_sum = (uint64_t)x + (uint64_t)y + (uint64_t)(*carry ? 1 : 0);
    int64_t signed_sum = (int64_t)(int32_t)x + (int64_t)(int32_t)y + (int64_t)(*carry ? 1 : 0);

    uint32_t result = unsigned_sum & 0xFFFFFFFF;
    assert(result == (signed_sum & 0xFFFFFFFF));

    *carry = result != unsigned_sum;
    *overflow = (int64_t)(int32_t)result != signed_sum;

    return result;
}

uint32_t Shift_C(uint32_t value, arm_shifter type, uint32_t amount, bool *carry)
{
    if (type == ARM_SFT_RRX)
    {
        uint32_t result = (value >> 1) | (*carry << 31);
        *carry = value & 1;
        return result;
    }

    if (amount == 0)
        return value;

    // assert(amount < 32);

    switch (type)
    {
    case ARM_SFT_LSL:
        assert(amount < 32);

        *carry = (value >> (32 - amount)) & 1;
        return value << amount;

    case ARM_SFT_LSR:
        assert(amount < 32);

        *carry = (value >> (amount - 1)) & 1;
        return value >> amount;

    case ARM_SFT_ASR:
        if (amount > 31)
        {
            *carry = value >> 31;
            return (int32_t)value >> 31;
        }

        *carry = (value >> (amount - 1)) & 1;
        return (int32_t)value >> amount;

    case ARM_SFT_ROR:
        *carry = (value >> (amount - 1)) & 1;
        return (value >> amount) | (value << (32 - amount));

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

// Capstone doesn't provide the carry bit so we must calculate it ourselves
static inline bool CalculateThumbExpandCarry(uint8_t *bytes, uint32_t imm32, bool carry_in)
{
    bool bit1 = (bytes[1] & (1 << 2)) != 0;
    bool bit2 = (bytes[3] & (1 << 6)) != 0;

    if (bit1 || bit2)
        return (imm32 & (1 << 31)) != 0;

    return carry_in;
}
