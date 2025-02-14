cmake_minimum_required(VERSION 3.13)

project(infiniemu)

if(CMAKE_TOOLCHAIN_FILE MATCHES "Emscripten.cmake")
    set(EMSCRIPTEN TRUE)
    message("[*] Building using Emscripten toolchain")
endif()

find_package(PNG REQUIRED)

include("./cmake/bundle.cmake")

include_directories(include lib .)

add_subdirectory(lib/tiny-AES-c)

option(CAPSTONE_ARCHITECTURE_DEFAULT "" OFF)
option(CAPSTONE_ARM_SUPPORT "" ON)
add_subdirectory(lib/capstone)

add_library(lua STATIC lib/lua/onelua.c)
target_compile_options(lua PRIVATE -DMAKE_LIB)

add_subdirectory(src)
