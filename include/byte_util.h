#pragma once

#define READ_UINT32(arr, addr) (arr[(addr)] | (arr[(addr)+1] << 8) | (arr[(addr)+2] << 16) | (arr[(addr)+3] << 24))
#define WRITE_UINT32(arr, addr, value) do { \
    (arr)[(addr)] = (value) & 0xFF; \
    (arr)[(addr)+1] = ((value) >> 8) & 0xFF; \
    (arr)[(addr)+2] = ((value) >> 16) & 0xFF; \
    (arr)[(addr)+3] = ((value) >> 24) & 0xFF; } while (0);

#define x(high, low) 0x##high##low