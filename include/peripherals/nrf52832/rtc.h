#include "peripherals/peripheral.h"

#include "cpu.h"

#define RTC_MAX_CC 4

NRF52_PERIPHERAL(RTC, rtc, size_t cc_num)
