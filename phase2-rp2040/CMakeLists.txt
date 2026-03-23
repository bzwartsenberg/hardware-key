cmake_minimum_required(VERSION 3.13)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(fido-authenticator C CXX ASM)
set(CMAKE_C_STANDARD 11)

# Point mbedtls at our minimal config (only SHA-256, AES, HMAC enabled).
# This must be set BEFORE pico_sdk_init() because the SDK reads it during init.
set(PICO_MBEDTLS_CONFIG_FILE "fido_mbedtls_config.h")

pico_sdk_init()

# --- micro-ecc library ---
# We build it as a static library and tell it to only include the P-256 curve
# we need. This saves code space — no point compiling secp160r1 etc.
add_library(micro_ecc STATIC lib/micro-ecc/uECC.c)
target_include_directories(micro_ecc PUBLIC lib/micro-ecc)
target_compile_definitions(micro_ecc PUBLIC
    uECC_SUPPORTS_secp160r1=0
    uECC_SUPPORTS_secp192r1=0
    uECC_SUPPORTS_secp224r1=0
    uECC_SUPPORTS_secp256r1=1
    uECC_SUPPORTS_secp256k1=0
    uECC_OPTIMIZATION_LEVEL=3
)

# --- Common settings for all targets ---
# Shared source files, includes, and libraries used by both the main
# firmware and the test targets.
set(COMMON_SOURCES src/crypto.c)
set(COMMON_LIBS pico_stdlib pico_rand pico_mbedtls micro_ecc)

# --- Main firmware ---
# The authenticator uses all layers: crypto, CTAPHID transport, and U2F commands.
# No printf/debug output — the serial port carries raw binary CTAPHID packets.
add_executable(authenticator
    src/main.c
    src/ctaphid.c
    src/u2f.c
    src/storage.c
    src/button.c
    ${COMMON_SOURCES}
)
target_include_directories(authenticator PRIVATE include)
target_link_libraries(authenticator ${COMMON_LIBS} hardware_flash hardware_sync)
pico_enable_stdio_usb(authenticator 1)
pico_enable_stdio_uart(authenticator 0)
pico_add_extra_outputs(authenticator)

# --- Crypto test ---
# Build with: make test_crypto
# Exercises all crypto functions and prints timing benchmarks over serial.
add_executable(test_crypto
    src/test_crypto.c
    ${COMMON_SOURCES}
)
target_include_directories(test_crypto PRIVATE include)
target_link_libraries(test_crypto ${COMMON_LIBS})
target_compile_definitions(test_crypto PRIVATE DEBUG_CRYPTO)
pico_enable_stdio_usb(test_crypto 1)
pico_enable_stdio_uart(test_crypto 0)
pico_add_extra_outputs(test_crypto)
