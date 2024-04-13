#include "peripherals/peripheral.h"

#define RTC_MAX_CC 4

PERIPHERAL(RTC, rtc, size_t cc_num)

void rtc_tick(RTC_t *rtc);
