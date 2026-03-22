/**
 * Minimal mbedtls configuration for FIDO U2F authenticator.
 *
 * We only enable what we actually call:
 *   - SHA-256 (hashing before ECDSA sign, key derivation)
 *   - AES-256-CBC (key wrapping)
 *   - HMAC via MD (key derivation, key handle integrity)
 *
 * ECDSA is handled entirely by micro-ecc, not mbedtls.
 *
 * mbedtls v3 uses a "default everything on" approach in its stock config.
 * We override that completely — only defining what we need keeps the
 * firmware small (~10 KB for mbedtls instead of ~100+ KB).
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// --- Core modules we need ---

// SHA-256 hashing
#define MBEDTLS_SHA256_C

// AES encryption (for CBC key wrapping)
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC

// MD (message digest) module — HMAC-SHA256 goes through this
#define MBEDTLS_MD_C

// --- Platform setup for bare-metal RP2040 ---

// No OS-level entropy source (we use pico_rand instead)
#define MBEDTLS_NO_PLATFORM_ENTROPY

// Tell mbedtls there's no filesystem (no /dev/urandom, no cert files)
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES

// We don't use mbedtls's memory allocation — all our buffers are stack/static
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

// But we do need printf for error reporting
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO snprintf

#endif // MBEDTLS_CONFIG_H
