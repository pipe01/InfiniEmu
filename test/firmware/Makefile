NRFX_MDK = $(NRFX_PATH)/mdk

CC = $(ARM_TOOLCHAIN_PATH)/bin/arm-none-eabi-gcc
CC_FLAGS = --specs=nosys.specs -mcpu=cortex-m4 -mthumb -mabi=aapcs -mfloat-abi=soft -lnosys

SDK_DEFS += NRF52 NRF52832 NRF52832_XXAA BOARD_PCA10040

SDK_INCLUDES += $(NRF5_SDK_PATH)/components/toolchain/cmsis/include

all: firmware.bin firmware.dis firmware.readelf
.PHONY: all

firmware.elf: main.c
	$(CC) $(CC_FLAGS) $(addprefix -D,$(SDK_DEFS)) $(addprefix -I,$(SDK_INCLUDES)) -o $@ $(NRFX_MDK)/system_nrf52.c $(NRFX_MDK)/gcc_startup_nrf52.S $< -L $(NRFX_MDK) -Tnrf52832_xxaa.ld

firmware.bin: firmware.elf
	$(ARM_TOOLCHAIN_PATH)/bin/arm-none-eabi-objcopy -O binary $< $@

firmware.readelf: firmware.elf
	$(ARM_TOOLCHAIN_PATH)/bin/arm-none-eabi-readelf -a $< > $@

firmware.dis: firmware.elf
	$(ARM_TOOLCHAIN_PATH)/bin/arm-none-eabi-objdump -D --visualize-jumps $< > $@
