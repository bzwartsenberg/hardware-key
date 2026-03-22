# Every Pico project starts with these three lines.
# They pull in the SDK's build system before your project is defined.
cmake_minimum_required(VERSION 3.13)

# This include defines pico_sdk_init() and all the SDK's CMake functions.
# It reads PICO_SDK_PATH from environment to find the SDK.
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

# Now declare your project — plain CMake.
project(blink C CXX ASM)
set(CMAKE_C_STANDARD 11)

# Initialize the SDK. This sets up the toolchain, boot stage2,
# and makes all the pico_* libraries available to link against.
pico_sdk_init()

# Define your executable — just like any CMake project.
add_executable(blink main.c)

# Link against the SDK libraries you need.
# pico_stdlib gives you: GPIO, clocks, printf, stdio (serial or USB).
target_link_libraries(blink pico_stdlib)

# This generates the .uf2 file alongside the .elf.
# Without it you'd only get an .elf (which needs a debugger to flash).
pico_add_extra_outputs(blink)
