#pragma once

#include "peripherals/peripheral.h"

typedef enum
{
    RESETREASON_RESETPIN = 1 << 0, // Reset from pin-reset detected
    RESETREASON_DOG = 1 << 1,      // Reset from watchdog detected
    RESETREASON_SREQ = 1 << 2,     // Reset from soft reset detected
    RESETREASON_LOCKUP = 1 << 3,   // Reset from CPU lock-up detected
    RESETREASON_OFF = 1 << 16,     // Reset due to wake up from System OFF mode when wakeup is triggered from DETECT signal from GPIO
    RESETREASON_LPCOMP = 1 << 17,  // Reset due to wake up from System OFF mode when wakeup is triggered from ANADETECT signal from LPCOMP
    RESETREASON_DIF = 1 << 18,     // Reset due to wake up from System OFF mode when wakeup is triggered from entering into debug interface mode
    RESETREASON_NFC = 1 << 19,     // Reset due to wake up from System OFF mode by NFC field detect
} nrf_resetreason;

NRF52_PERIPHERAL(POWER, power)
