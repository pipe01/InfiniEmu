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

set(WASM_EXPORTS
    malloc pinetime_new pinetime_step pinetime_loop
    pinetime_get_st7789 st7789_read_screen st7789_is_sleeping st7789_get_write_count st7789_is_sleeping
    pinetime_get_cst816s cst816s_do_touch cst816s_release_touch
    pinetime_get_nrf52832 nrf52832_get_pins pins_set pins_clear
)

if(EMSCRIPTEN)
    list(TRANSFORM WASM_EXPORTS PREPEND "_" OUTPUT_VARIABLE WASM_EXPORTS)
    list(JOIN WASM_EXPORTS "," WASM_EXPORTS_STR)

    add_link_options("-sEXPORTED_FUNCTIONS=${WASM_EXPORTS_STR}")
    add_link_options(-sTOTAL_STACK=64MB -sALLOW_MEMORY_GROWTH -sEXPORTED_RUNTIME_METHODS=ccall,cwrap)
endif()

add_executable(infiniemu-cli ${SRC_FILES} infiniemu.c)
add_library(infiniemu-lib STATIC ${SRC_FILES})

target_link_libraries(infiniemu-cli PUBLIC m tiny-aes capstone)
target_link_libraries(infiniemu-lib PUBLIC m tiny-aes capstone)

set_property(TARGET infiniemu-lib PROPERTY OUTPUT_NAME infiniemu)

if(EMSCRIPTEN)
    set_property(TARGET infiniemu-cli PROPERTY OUTPUT_NAME infiniemu)
endif()

bundle_static_library(infiniemu-lib infiniemu_bundle)
