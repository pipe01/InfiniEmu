#pragma once

#define ARM_EXCEPTION_RESET 1
#define ARM_EXCEPTION_NMI 2
#define ARM_EXCEPTION_HARDFAULT 3
#define ARM_EXCEPTION_MEMMANAGE 4
#define ARM_EXCEPTION_BUSFAULT 5
#define ARM_EXCEPTION_USAGEFAULT 6
#define ARM_EXCEPTION_SVC 11
#define ARM_EXCEPTION_DEBUGMONITOR 12
#define ARM_EXCEPTION_PENDSV 14
#define ARM_EXCEPTION_SYSTICK 15

#define APSR_N 31
#define APSR_Z 30
#define APSR_C 29
#define APSR_V 28
#define APSR_Q 27
#define APSR_GE (0b1111 << 16)

#define EPSR_T 24

#define CONTROL_nPRIV 0
#define CONTROL_SPSEL 1
#define CONTROL_FPCA 2

typedef enum
{
    ARM_MODE_THREAD = 0,
    ARM_MODE_HANDLER = 1,
} arm_mode;

typedef enum
{
    ARM_RESETREASON_RESETPIN = 1 << 0, // Reset from pin-reset detected
    ARM_RESETREASON_DOG = 1 << 1,      // Reset from watchdog detected
    ARM_RESETREASON_SREQ = 1 << 2,     // Reset from soft reset detected
    ARM_RESETREASON_LOCKUP = 1 << 3,   // Reset from CPU lock-up detected
    ARM_RESETREASON_OFF = 1 << 16,     // Reset due to wake up from System OFF mode when wakeup is triggered from DETECT signal from GPIO
    ARM_RESETREASON_LPCOMP = 1 << 17,  // Reset due to wake up from System OFF mode when wakeup is triggered from ANADETECT signal from LPCOMP
    ARM_RESETREASON_DIF = 1 << 18,     // Reset due to wake up from System OFF mode when wakeup is triggered from entering into debug interface mode
    ARM_RESETREASON_NFC = 1 << 19,     // Reset due to wake up from System OFF mode by NFC field detect
} arm_resetreason;
