set(SRC_FILES
    bus_i2c.c
    bus_spi.c
    circular_buffer.c
    commander.c
    cpu.c
    dma.c
    fault.c
    memory.c
    nrf52832.c
    pinetime.c
    pins.c
    program.c
    scheduler.c
    segger_rtt.c
    state_store.c
    ticker.c

    demangle.cpp

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

    ../lib/littlefs/lfs.c       # TODO: Include littlefs from root CMakeLists.txt
    ../lib/littlefs/lfs_util.c
)

set(SRC_WASM_FILES
    wasm.c
)

set(SRC_NATIVE_FILES
    gdb.c
    main.c
    pcap.c
    runlog.c
    time.c
)

# Disable warnings for littlefs
set_source_files_properties(../lib/littlefs/lfs.c PROPERTIES COMPILE_FLAGS "-w")

set(WASM_EXPORTS
    malloc free
    pinetime_new pinetime_step pinetime_loop pinetime_reset
    pinetime_get_st7789 st7789_read_screen_rgba st7789_is_sleeping st7789_get_write_count st7789_is_sleeping
    pinetime_get_cst816s cst816s_do_touch cst816s_release_touch
    pinetime_get_nrf52832 nrf52832_get_sram_size nrf52832_get_pins pins_set pins_clear pins_read_all
    pinetime_get_spinorflash spinorflash_get_buffer spinorflash_get_buffer_size
    nrf52832_get_cpu cpu_is_sleeping cpu_mem
    program_new program_load_binary program_load_elf program_write_variable
    commander_new commander_set_wasm_output commander_run_command commander_output
    rtt_new rtt_find_control rtt_flush_buffers
    lfs_init lfs_mkdir lfs_free_wasm lfs_open_dir lfs_dir_read
    lfs_open_file lfs_file_close lfs_file_read lfs_file_write
    lfs_info_malloc lfs_info_type lfs_info_size lfs_info_name
)

set(LIBS m tiny-aes capstone)

add_compile_options(-Werror -Wall -Wextra -Wno-unused-parameter)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_definitions(_POSIX_C_SOURCE=200809L)

set_source_files_properties(demangle.c PROPERTIES LANGUAGE CXX)

if(EMSCRIPTEN)
    list(APPEND SRC_FILES ${SRC_WASM_FILES})
    add_compile_definitions(WASM=1)

    add_executable(infiniemu-wasm ${SRC_FILES})
    target_link_libraries(infiniemu-wasm PUBLIC ${LIBS})
    set_property(TARGET infiniemu-wasm PROPERTY OUTPUT_NAME infiniemu)

    list(TRANSFORM WASM_EXPORTS PREPEND "_" OUTPUT_VARIABLE WASM_EXPORTS)
    list(JOIN WASM_EXPORTS "," WASM_EXPORTS_STR)

    target_link_options(infiniemu-wasm PRIVATE "-sEXPORTED_FUNCTIONS=${WASM_EXPORTS_STR}")
    target_link_options(infiniemu-wasm PRIVATE
        -sTOTAL_STACK=64MB
        -sALLOW_MEMORY_GROWTH
        -sEXPORTED_RUNTIME_METHODS=ccall,cwrap,stringToNewUTF8,UTF8ToString
        -sMODULARIZE=1
        -sEXPORT_ES6=1
    )
else()
    list(APPEND SRC_FILES ${SRC_NATIVE_FILES})
    add_compile_definitions(ENABLE_RUNLOG=1 ENABLE_PCAP=1)

    add_executable(infiniemu-cli ${SRC_FILES})
    add_library(infiniemu-lib STATIC ${SRC_FILES})

    target_link_libraries(infiniemu-cli PUBLIC ${LIBS})
    target_link_libraries(infiniemu-lib PUBLIC ${LIBS})

    set_property(TARGET infiniemu-lib PROPERTY OUTPUT_NAME infiniemu)

    bundle_static_library(infiniemu-lib infiniemu_bundle)
endif()
