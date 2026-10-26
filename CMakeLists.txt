cmake_minimum_required(VERSION 3.21)

# Default to Clang while allowing explicit compiler or toolchain overrides.

if(NOT DEFINED CMAKE_CXX_COMPILER AND "$ENV{CXX}" STREQUAL "")
    find_program(CMAKE_CXX_COMPILER NAMES clang++ REQUIRED)
endif()

project(pcapng_push LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS_DEBUG "-g -Og -ggdb -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_SANITIZE
    "-g -Og -fno-omit-frame-pointer -fsanitize=address,undefined")
set(CMAKE_CXX_FLAGS_RELEASE
    "-O2 -DNDEBUG -march=native -flto=full -mtune=native -funroll-loops")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build configuration" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Sanitize Release)
if(CMAKE_CONFIGURATION_TYPES)
    list(APPEND CMAKE_CONFIGURATION_TYPES Sanitize)
    list(REMOVE_DUPLICATES CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING
        "Available build configurations" FORCE)
endif()

file(GLOB SOURCES CONFIGURE_DEPENDS

    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)
add_executable(binary ${SOURCES})
set_target_properties(binary PROPERTIES

    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)
# io_uring
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBURING REQUIRED IMPORTED_TARGET liburing)

target_link_libraries(binary PRIVATE PkgConfig::LIBURING)


target_compile_options(binary PRIVATE -Wall -Wextra)
target_link_options(binary PRIVATE -fuse-ld=mold)

