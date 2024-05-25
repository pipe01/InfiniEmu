#include "peripherals/peripheral.h"

#include "cpu.h"

#define RTC_MAX_CC 4

PERIPHERAL(RTC, rtc, size_t cc_num, cpu_t **cpu, uint8_t id)

void rtc_tick(RTC_t *rtc);
