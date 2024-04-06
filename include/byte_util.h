#pragma once

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