#pragma once

#define READ_UINT32(arr, addr) (arr[(addr)] | (arr[(addr)+1] << 8) | (arr[(addr)+2] << 16) | (arr[(addr)+3] << 24))