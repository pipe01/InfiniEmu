#pragma once

#include "peripherals/peripheral.h"

#include "cpu.h"

#define RTC_MAX_CC 4

enum
{
    RTC_TASKS_START = 0x000,
    RTC_TASKS_STOP = 0x004,
    RTC_TASKS_CLEAR = 0x008,
    RTC_TASKS_TRIGOVRFLW = 0x00C,
    RTC_EVENTS_TICK = 0x100,
    RTC_EVENTS_OVRFLW = 0x104,
    RTC_EVENTS_COMPARE0 = 0x140,
    RTC_EVENTS_COMPARE1 = 0x144,
    RTC_EVENTS_COMPARE2 = 0x148,
    RTC_EVENTS_COMPARE3 = 0x14C,
};

NRF52_PERIPHERAL(RTC, rtc, size_t cc_num)

uint32_t rtc_is_running(RTC_t *);
uint32_t rtc_get_counter(RTC_t *);
double rtc_get_tick_interval_us(RTC_t *);
