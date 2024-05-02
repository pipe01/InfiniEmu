#pragma once

#include <stdint.h>

#if !defined(__BYTE_ORDER__) || (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error This program only works on little endian systems
#endif

typedef union {
    struct {
        uint8_t a : 8;
        uint8_t b : 8;
        uint8_t c : 8;
        uint8_t d : 8;
    };
    uint8_t u8[4];
    uint32_t u32;
} Register4;

typedef union {
    struct {
        uint16_t a : 16;
        uint16_t b : 16;
    };
    uint16_t u16[2];
    uint32_t u32;
} Register2;

#define READ_UINT16(arr, addr) (arr[(addr)] | (arr[(addr)+1] << 8))
#define WRITE_UINT16(arr, addr, value) do { \
    (arr)[(addr)] = (value) & 0xFF; \
    (arr)[(addr)+1] = ((value) >> 8) & 0xFF; } while (0);

#define READ_UINT32(arr, addr) (arr[(addr)] | (arr[(addr)+1] << 8) | (arr[(addr)+2] << 16) | (arr[(addr)+3] << 24))
#define WRITE_UINT32(arr, addr, value) do { \
    (arr)[(addr)] = (value) & 0xFF; \
    (arr)[(addr)+1] = ((value) >> 8) & 0xFF; \
    (arr)[(addr)+2] = ((value) >> 16) & 0xFF; \
    (arr)[(addr)+3] = ((value) >> 24) & 0xFF; } while (0);

#define x(high, low) 0x##high##low

// x & (0xFFFFFFFF << log2(n))
#define ALIGN2(x) ((x) & (0xFFFFFFFF << 1))
#define ALIGN4(x) ((x) & (0xFFFFFFFF << 2))
#define ALIGN8(x) ((x) & (0xFFFFFFFF << 3))

#define SET(x, n) ((x) = ((x) | (1 << (n))))
#define CLEAR(x, n) ((x) = ((x) & ~(1 << (n))))
#define IS_SET(x, n) (((x) & (1 << (n))) != 0)

#define MASK(n) (1 << (n))
