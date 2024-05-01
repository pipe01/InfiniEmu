NRFX_MDK = $(NRFX_PATH)/mdk
FREERTOS = 0

CC = $(ARM_TOOLCHAIN_PATH)/bin/arm-none-eabi-gcc
CC_FLAGS = --specs=nosys.specs -mcpu=cortex-m4 -mthumb -mabi=aapcs -lnosys -mfloat-abi=hard -mfpu=fpv4-sp-d16

FILES += main.c

SDK_DEFS = NRF52 NRF52832 NRF52832_XXAA BOARD_PCA10040

ifeq ($(FREERTOS),1)
	FILES += $(wildcard FreeRTOS/*.c)
	SDK_FILES += external/freertos/source/croutine.c
	SDK_FILES += external/freertos/source/event_groups.c
	SDK_FILES += external/freertos/source/list.c
	SDK_FILES += external/freertos/source/queue.c
	SDK_FILES += external/freertos/source/stream_buffer.c
	SDK_FILES += external/freertos/source/tasks.c
	SDK_FILES += external/freertos/source/timers.c
endif

SDK_FILES += components/libraries/atomic/nrf_atomic.c
SDK_FILES += components/libraries/balloc/nrf_balloc.c
SDK_FILES += components/libraries/util/nrf_assert.c
SDK_FILES += components/libraries/util/app_error.c
SDK_FILES += components/libraries/util/app_error_weak.c
SDK_FILES += components/libraries/util/app_error_handler_gcc.c
SDK_FILES += components/libraries/util/app_util_platform.c
SDK_FILES += components/libraries/log/src/nrf_log_backend_rtt.c
SDK_FILES += components/libraries/log/src/nrf_log_backend_serial.c
SDK_FILES += components/libraries/log/src/nrf_log_default_backends.c
SDK_FILES += components/libraries/log/src/nrf_log_frontend.c
SDK_FILES += components/libraries/log/src/nrf_log_str_formatter.c
SDK_FILES += components/libraries/memobj/nrf_memobj.c
SDK_FILES += components/libraries/ringbuf/nrf_ringbuf.c
SDK_FILES += components/libraries/strerror/nrf_strerror.c

SDK_FILES += components/boards/boards.c
SDK_FILES += integration/nrfx/legacy/nrf_drv_clock.c
SDK_FILES += integration/nrfx/legacy/nrf_drv_clock.h
SDK_FILES += modules/nrfx/drivers/src/nrfx_clock.c
SDK_FILES += modules/nrfx/drivers/src/nrfx_gpiote.c
SDK_FILES += modules/nrfx/soc/nrfx_atomic.c
SDK_FILES += modules/nrfx/drivers/src/nrfx_saadc.c

SDK_INCLUDES += components/drivers_nrf/nrf_soc_nosd
SDK_INCLUDES += components
SDK_INCLUDES += components/boards
SDK_INCLUDES += components/softdevice/common
SDK_INCLUDES += integration/nrfx
SDK_INCLUDES += integration/nrfx/legacy
SDK_INCLUDES += modules/nrfx
SDK_INCLUDES += modules/nrfx/drivers/include
SDK_INCLUDES += modules/nrfx/hal
SDK_INCLUDES += modules/nrfx/mdk
SDK_INCLUDES += external/freertos/source/include
SDK_INCLUDES += components/toolchain/cmsis/include
SDK_INCLUDES += components/libraries/atomic
SDK_INCLUDES += components/libraries/atomic_fifo
SDK_INCLUDES += components/libraries/atomic_flags
SDK_INCLUDES += components/libraries/balloc
SDK_INCLUDES += components/libraries/bootloader/ble_dfu
SDK_INCLUDES += components/libraries/cli
SDK_INCLUDES += components/libraries/crc16
SDK_INCLUDES += components/libraries/crc32
SDK_INCLUDES += components/libraries/crypto
SDK_INCLUDES += components/libraries/csense
SDK_INCLUDES += components/libraries/csense_drv
SDK_INCLUDES += components/libraries/delay
SDK_INCLUDES += components/libraries/ecc
SDK_INCLUDES += components/libraries/experimental_section_vars
SDK_INCLUDES += components/libraries/experimental_task_manager
SDK_INCLUDES += components/libraries/fds
SDK_INCLUDES += components/libraries/fstorage
SDK_INCLUDES += components/libraries/gfx
SDK_INCLUDES += components/libraries/gpiote
SDK_INCLUDES += components/libraries/hardfault
SDK_INCLUDES += components/libraries/hci
SDK_INCLUDES += components/libraries/led_softblink
SDK_INCLUDES += components/libraries/log
SDK_INCLUDES += components/libraries/log/src
SDK_INCLUDES += components/libraries/low_power_pwm
SDK_INCLUDES += components/libraries/mem_manager
SDK_INCLUDES += components/libraries/memobj
SDK_INCLUDES += components/libraries/mpu
SDK_INCLUDES += components/libraries/mutex
SDK_INCLUDES += components/libraries/pwm
SDK_INCLUDES += components/libraries/pwr_mgmt
SDK_INCLUDES += components/libraries/queue
SDK_INCLUDES += components/libraries/ringbuf
SDK_INCLUDES += components/libraries/scheduler
SDK_INCLUDES += components/libraries/sdcard
SDK_INCLUDES += components/libraries/slip
SDK_INCLUDES += components/libraries/sortlist
SDK_INCLUDES += components/libraries/spi_mngr
SDK_INCLUDES += components/libraries/stack_guard
SDK_INCLUDES += components/libraries/strerror
SDK_INCLUDES += components/libraries/svc
SDK_INCLUDES += components/libraries/timer
SDK_INCLUDES += components/libraries/usbd
SDK_INCLUDES += components/libraries/usbd/class/audio
SDK_INCLUDES += components/libraries/usbd/class/cdc
SDK_INCLUDES += components/libraries/usbd/class/cdc/acm
SDK_INCLUDES += components/libraries/usbd/class/hid
SDK_INCLUDES += components/libraries/usbd/class/hid/generic
SDK_INCLUDES += components/libraries/usbd/class/hid/kbd
SDK_INCLUDES += components/libraries/usbd/class/hid/mouse
SDK_INCLUDES += components/libraries/usbd/class/msc
SDK_INCLUDES += components/libraries/util
SDK_INCLUDES += external/segger_rtt/
SDK_INCLUDES += external/fprintf/
SDK_INCLUDES += external/thedotfactory_fonts
SDK_INCLUDES += components/libraries/gpiote

all: firmware.bin firmware.dis firmware.readelf
.PHONY: all

firmware.elf: $(FILES) $(addprefix ${NRF5_SDK_PATH}/,$(SDK_FILES))
	$(CC) $(CC_FLAGS) $(addprefix -D,$(SDK_DEFS)) -I. -IFreeRTOS $(addprefix -I${NRF5_SDK_PATH}/,$(SDK_INCLUDES)) -o $@ $(NRFX_MDK)/system_nrf52.c $(NRFX_MDK)/gcc_startup_nrf52.S $^ -L $(NRFX_MDK) -Tnrf52832_xxaa.ld

firmware.bin: firmware.elf
	$(ARM_TOOLCHAIN_PATH)/bin/arm-none-eabi-objcopy -O binary $< $@

firmware.readelf: firmware.elf
	$(ARM_TOOLCHAIN_PATH)/bin/arm-none-eabi-readelf -a $< > $@

firmware.dis: firmware.elf
	$(ARM_TOOLCHAIN_PATH)/bin/arm-none-eabi-objdump -D --visualize-jumps $< > $@
