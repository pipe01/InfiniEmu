set(SRC_FILES
    bus_i2c.c
    bus_spi.c
    cpu.c
    dma.c
    fault.c
    gdb.c
    memory.c
    nrf52832.c
    pinetime.c
    pins.c
    runlog.c
    scheduler.c
    segger_rtt.c
    ticker.c
    wasm.c

    component/i2c/bma425.c
    component/i2c/cst816s.c
    component/i2c/hrs3300.c

    component/spi/spinorflash.c
    component/spi/st7789.c

    peripherals/dcb.c
    peripherals/dwt.c
    peripherals/nvic.c
    peripherals/scb_fp.c
    peripherals/scb.c

    peripherals/nrf52832/ccm.c
    peripherals/nrf52832/clock.c
    peripherals/nrf52832/comp.c
    peripherals/nrf52832/ecb.c
    peripherals/nrf52832/gpio.c
    peripherals/nrf52832/gpiote.c
    peripherals/nrf52832/power.c
    peripherals/nrf52832/ppi.c
    peripherals/nrf52832/radio.c
    peripherals/nrf52832/rng.c
    peripherals/nrf52832/rtc.c
    peripherals/nrf52832/saadc.c
    peripherals/nrf52832/spim.c
    peripherals/nrf52832/temp.c
    peripherals/nrf52832/timer.c
    peripherals/nrf52832/twim.c
    peripherals/nrf52832/wdt.c
)

add_executable(infiniemu-cli ${SRC_FILES} infiniemu.c)
add_library(infiniemu-lib STATIC ${SRC_FILES})

target_link_libraries(infiniemu-cli PUBLIC m tiny-aes capstone)
target_link_libraries(infiniemu-lib PUBLIC m tiny-aes capstone)

set_property(TARGET infiniemu-lib PROPERTY OUTPUT_NAME infiniemu)

bundle_static_library(infiniemu-lib infiniemu_bundle)
