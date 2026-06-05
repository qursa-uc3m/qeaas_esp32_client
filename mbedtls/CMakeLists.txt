#
# mbedtls/CMakeLists.txt
#
# Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
#
# CMake configuration for BLAKE2s Entropy Pool Test Program
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(blake2s_entropy_pool_test)

zephyr_include_directories(include)

target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_sources(app PRIVATE src/main.c)

message(STATUS "...............................................")
message(STATUS "ZEPHYR_EXTRA_MODULES after Zephyr package: ${ZEPHYR_EXTRA_MODULES}")
message(STATUS "Project: BLAKE2s Entropy Pool Test Suite")
message(STATUS "...............................................")