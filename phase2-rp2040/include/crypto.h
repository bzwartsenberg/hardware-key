#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// --- Sizes ---
// These match the FIDO spec and our Phase 1 Python implementation.

#define MASTER_SECRET_SIZE   32
#define PRIVATE_KEY_SIZE     32
#define PUBLIC_KEY_SIZE      65   // 0x04 || X (32) || Y (32), uncompressed
#define RAW_PUBLIC_KEY_SIZE  64   // X (32) || Y (32), what micro-ecc uses internally
#define SIGNATURE_MAX_SIZE   72   // DER-encoded ECDSA sig (variable, typically 70-72)
#define KEY_HANDLE_SIZE      96   // IV (16) + ciphertext (48) + HMAC (32)
#define AES_IV_SIZE          16
#define AES_BLOCK_SIZE       16
#define SHA256_SIZE          32
#define HMAC_TAG_SIZE        32

// --- Initialization ---
// Must be called once at startup. Sets up the RNG for micro-ecc
// using the RP2040's ring oscillator entropy source.
void crypto_init(void);

// --- Key generation ---
// Generate an ECDSA P-256 key pair.
// public_key:  65 bytes out (0x04 || X || Y)
// private_key: 32 bytes out
// Returns true on success.
bool crypto_generate_keypair(uint8_t *public_key, uint8_t *private_key);

// --- Signing ---
// Sign data with ECDSA P-256. Hashes data with SHA-256 internally,
// then signs the hash — same as Phase 1's crypto.sign().
// signature:     output buffer (must be SIGNATURE_MAX_SIZE bytes)
// signature_len: actual length of the DER-encoded signature
// Returns true on success.
bool crypto_sign(const uint8_t *private_key,
                 const uint8_t *data, size_t data_len,
                 uint8_t *signature, size_t *signature_len);

// --- Verification ---
// Verify an ECDSA P-256 signature (DER-encoded).
// public_key: 65 bytes (0x04 || X || Y)
bool crypto_verify(const uint8_t *public_key,
                   const uint8_t *data, size_t data_len,
                   const uint8_t *signature, size_t signature_len);

// --- Key wrapping ---
// Encrypt a private key into a key handle using the master secret.
// key_handle: KEY_HANDLE_SIZE bytes out
bool crypto_wrap_key(const uint8_t *master_secret,
                     const uint8_t *private_key,
                     uint8_t *key_handle);

// Decrypt a key handle back into a private key.
// Returns true if HMAC verified and decryption succeeded.
// Returns false if the key handle is invalid (wrong device or tampered).
bool crypto_unwrap_key(const uint8_t *master_secret,
                       const uint8_t *key_handle,
                       uint8_t *private_key);

// --- Utility ---
// SHA-256 hash.
void crypto_sha256(const uint8_t *data, size_t len, uint8_t *hash_out);

// Fill buffer with random bytes.
void crypto_random(uint8_t *buf, size_t len);

// Print a hex dump (for debug output over serial).
void crypto_print_hex(const char *label, const uint8_t *data, size_t len);

#endif // CRYPTO_H
