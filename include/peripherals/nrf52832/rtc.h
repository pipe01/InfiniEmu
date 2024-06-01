#include "peripherals/peripheral.h"

#include "cpu.h"

#define RTC_MAX_CC 4

NRF52_PERIPHERAL(RTC, rtc, size_t cc_num)

uint32_t rtc_get_counter(RTC_t *);
uint32_t rtc_get_tick_interval_us(RTC_t *);
