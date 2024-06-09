cmake_minimum_required(VERSION 3.10)

project(infiniemu)

include("./cmake/bundle.cmake")

include_directories(include lib)

add_subdirectory(lib/tiny-AES-c)

option(CAPSTONE_ARCHITECTURE_DEFAULT "" OFF)
option(CAPSTONE_ARM_SUPPORT "" ON)
add_subdirectory(lib/capstone)

add_subdirectory(src)
