set(SRC_FILES
    bus_i2c.c
    bus_spi.c
    circular_buffer.c
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
    peripherals/nrf52832/nvmc.c
    peripherals/nrf52832/power.c
    peripherals/nrf52832/ppi.c
    peripherals/nrf52832/radio.c
    peripherals/nrf52832/rng.c
    peripherals/nrf52832/rtc.c
    peripherals/nrf52832/saadc.c
    peripherals/nrf52832/spi.c
    peripherals/nrf52832/spim.c
    peripherals/nrf52832/temp.c
    peripherals/nrf52832/timer.c
    peripherals/nrf52832/twim.c
    peripherals/nrf52832/wdt.c
)

set(WASM_EXPORTS
    malloc pinetime_new pinetime_step pinetime_loop
    pinetime_get_st7789 st7789_read_screen_rgba st7789_is_sleeping st7789_get_write_count st7789_is_sleeping
    pinetime_get_cst816s cst816s_do_touch cst816s_release_touch
    pinetime_get_nrf52832 nrf52832_get_pins pins_set pins_clear
)

set(LIBS m tiny-aes capstone)

if(EMSCRIPTEN)
    list(APPEND SRC_FILES wasm.c)
    add_compile_definitions(WASM=1)

    add_executable(infiniemu-wasm ${SRC_FILES})
    target_link_libraries(infiniemu-wasm PUBLIC ${LIBS})
    set_property(TARGET infiniemu-wasm PROPERTY OUTPUT_NAME infiniemu)

    list(TRANSFORM WASM_EXPORTS PREPEND "_" OUTPUT_VARIABLE WASM_EXPORTS)
    list(JOIN WASM_EXPORTS "," WASM_EXPORTS_STR)

    target_link_options(infiniemu-wasm PRIVATE "-sEXPORTED_FUNCTIONS=${WASM_EXPORTS_STR}")
    target_link_options(infiniemu-wasm PRIVATE -sTOTAL_STACK=64MB -sALLOW_MEMORY_GROWTH -sEXPORTED_RUNTIME_METHODS=ccall,cwrap)
else()
    add_executable(infiniemu-cli ${SRC_FILES} main.c)
    add_library(infiniemu-lib STATIC ${SRC_FILES})

    target_link_libraries(infiniemu-cli PUBLIC ${LIBS})
    target_link_libraries(infiniemu-lib PUBLIC ${LIBS})

    set_property(TARGET infiniemu-lib PROPERTY OUTPUT_NAME infiniemu)

    bundle_static_library(infiniemu-lib infiniemu_bundle)
endif()
