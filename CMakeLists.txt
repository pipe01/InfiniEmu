cmake_minimum_required(VERSION 3.13)

include(FetchContent)

project(infiniemu)

if(CMAKE_TOOLCHAIN_FILE MATCHES "Emscripten.cmake")
    set(EMSCRIPTEN TRUE)
    message("[*] Building using Emscripten toolchain")
endif()

find_package(PNG)
if(PNG_FOUND)
    add_compile_definitions(ENABLE_PNG=1)
endif()

include("./cmake/bundle.cmake")

include_directories(include lib .)

add_subdirectory(lib/tiny-AES-c)

option(CAPSTONE_ARCHITECTURE_DEFAULT "" OFF)
option(CAPSTONE_ARM_SUPPORT "" ON)
add_subdirectory(lib/capstone)

add_library(lua STATIC lib/lua/onelua.c)
target_compile_options(lua PRIVATE -DMAKE_LIB)

cmake_policy(SET CMP0135 NEW)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

add_subdirectory(src)
