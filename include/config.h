#pragma once

#include "user_config.h"

#ifndef ENABLE_LOG_GDB
#define ENABLE_LOG_GDB 0
#endif

#ifndef ENABLE_LOG_CPU_EXCEPTIONS
#define ENABLE_LOG_CPU_EXCEPTIONS 0
#endif

#ifndef ENABLE_LOG_CPU_INSTRUCTIONS
#define ENABLE_LOG_CPU_INSTRUCTIONS 0
#endif

#ifndef ENABLE_LOG_CPU_IT
#define ENABLE_LOG_CPU_IT 0
#endif

#ifndef ENABLE_LOG_SEGGER_RTT
#define ENABLE_LOG_SEGGER_RTT 1
#endif

#ifndef ENABLE_LOG_SPI_FLASH
#define ENABLE_LOG_SPI_FLASH 0
#endif

#ifndef ENABLE_LOG_BMA425
#define ENABLE_LOG_BMA425 0
#endif

#ifndef ENABLE_SEGGER_RTT
#define ENABLE_SEGGER_RTT 1
#endif

#ifndef ENABLE_MEASUREMENT
#define ENABLE_MEASUREMENT 0
#endif

#ifndef ABORT_ON_INVALID_MEM_ACCESS
#define ABORT_ON_INVALID_MEM_ACCESS 1
#endif

#ifndef ASSERT_EXCEPTION_REGISTERS
#define ASSERT_EXCEPTION_REGISTERS 0
#endif

#if WASM
#ifdef ENABLE_SEGGER_RTT
#undef ENABLE_SEGGER_RTT
#endif
#define ENABLE_SEGGER_RTT 0
#endif
