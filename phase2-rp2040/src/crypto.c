/**
 * Crypto layer for the FIDO U2F authenticator — RP2040 version.
 *
 * This is the C port of phase1-python-udp/crypto.py. Same operations,
 * same key handle format, same algorithms — just different libraries:
 *
 *   Python cryptography lib  →  micro-ecc (ECDSA) + mbedtls (SHA/AES/HMAC)
 *
 * Key difference: micro-ecc works with "raw" public keys (64 bytes, X||Y)
 * while FIDO expects "uncompressed" public keys (65 bytes, 0x04||X||Y).
 * We handle the 0x04 prefix in our wrapper functions.
 *
 * Another difference: micro-ecc's uECC_sign() produces a raw 64-byte
 * signature (r||s, 32 bytes each), but U2F expects DER-encoded signatures.
 * We convert between the two formats ourselves.
 */

#include "crypto.h"

#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/rand.h"
#include "uECC.h"

// mbedtls headers — these come from the Pico SDK's bundled mbedtls
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"       // HMAC lives in the "message digest" module


// -------------------------------------------------------------------------
// Debug output — compile with -DDEBUG_CRYPTO to enable verbose printing.
// Build the test_crypto target with: make test_crypto
// All debug output compiles to nothing in release builds.
// -------------------------------------------------------------------------
#ifdef DEBUG_CRYPTO
  #define DBG(...) printf(__VA_ARGS__)
  #define DBG_HEX(label, data, len) crypto_print_hex(label, data, len)
#else
  #define DBG(...) ((void)0)
  #define DBG_HEX(label, data, len) ((void)0)
#endif


// -------------------------------------------------------------------------
// RNG — feeding entropy to micro-ecc
// -------------------------------------------------------------------------
// micro-ecc needs a callback that fills a buffer with random bytes.
// On RP2040, pico_rand provides get_rand_128() which uses ring oscillator
// jitter. We wrap it to match micro-ecc's expected signature.

static int rng_callback(uint8_t *dest, unsigned size) {
    // get_rand_128() fills a 128-bit (16-byte) buffer with random data
    // from the RP2040's ring oscillator. We call it in a loop to fill
    // however many bytes are needed.
    while (size > 0) {
        rng_128_t val;
        get_rand_128(&val);  // fills val with 16 random bytes
        unsigned chunk = (size < 16) ? size : 16;
        memcpy(dest, &val, chunk);
        dest += chunk;
        size -= chunk;
    }
    return 1;  // 1 = success (micro-ecc convention)
}


void crypto_init(void) {
    // Register our RNG with micro-ecc. This MUST be called before
    // any key generation or signing — micro-ecc will crash without it.
    uECC_set_rng(rng_callback);
    DBG("[crypto] Initialized — RNG registered with micro-ecc\n");
}


// -------------------------------------------------------------------------
// Utility functions
// -------------------------------------------------------------------------

void crypto_random(uint8_t *buf, size_t len) {
    rng_callback(buf, (unsigned)len);
}


void crypto_sha256(const uint8_t *data, size_t len, uint8_t *hash_out) {
    // mbedtls_sha256() is a one-shot convenience function.
    // The last parameter: 0 = SHA-256, 1 = SHA-224.
    mbedtls_sha256(data, len, hash_out, 0);
}


void crypto_print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


// -------------------------------------------------------------------------
// HMAC-SHA256 — used for key derivation and key handle integrity
// -------------------------------------------------------------------------
// In Python we had: hmac.new(key, message, hashlib.sha256).digest()
// In mbedtls, HMAC is accessed through the "md" (message digest) module.

static void hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *mac_out) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md_info, key, key_len, data, data_len, mac_out);
}


// -------------------------------------------------------------------------
// Key derivation — same as Phase 1's _derive_wrapping_keys()
// -------------------------------------------------------------------------
// HMAC the master secret with labels to derive AES and HMAC keys.

static void derive_wrapping_keys(const uint8_t *master_secret,
                                  uint8_t *aes_key_out,
                                  uint8_t *hmac_key_out) {
    // aes_key  = HMAC-SHA256(master_secret, "u2f-aes-key")
    // hmac_key = HMAC-SHA256(master_secret, "u2f-hmac-key")
    // Same labels as Phase 1 — a key handle wrapped by the Python version
    // could theoretically be unwrapped by the C version if they share
    // the same master secret.
    hmac_sha256(master_secret, MASTER_SECRET_SIZE,
                (const uint8_t *)"u2f-aes-key", 11, aes_key_out);
    hmac_sha256(master_secret, MASTER_SECRET_SIZE,
                (const uint8_t *)"u2f-hmac-key", 12, hmac_key_out);

    DBG("  Key derivation:\n");
    DBG_HEX("AES key", aes_key_out, 32);
    DBG_HEX("HMAC key", hmac_key_out, 32);
}


// -------------------------------------------------------------------------
// PKCS7 padding — mbedtls AES-CBC doesn't pad for us
// -------------------------------------------------------------------------
// In Python, the cryptography library handled PKCS7 automatically.
// Here we do it ourselves. PKCS7 is simple: pad to block boundary by
// appending N bytes, each with value N. If already aligned, add a
// full block of 0x10 bytes.
//
// For our 32-byte private keys: 32 is exactly 2 AES blocks (16 bytes each),
// so PKCS7 adds a full block of padding → 48 bytes ciphertext.

static size_t pkcs7_pad(const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_size) {
    uint8_t pad_val = AES_BLOCK_SIZE - (in_len % AES_BLOCK_SIZE);
    size_t padded_len = in_len + pad_val;

    if (padded_len > out_size) return 0;

    memcpy(out, in, in_len);
    memset(out + in_len, pad_val, pad_val);
    return padded_len;
}


static size_t pkcs7_unpad(uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint8_t pad_val = data[len - 1];
    if (pad_val == 0 || pad_val > AES_BLOCK_SIZE) return 0;

    // Verify all padding bytes are correct
    for (size_t i = 0; i < pad_val; i++) {
        if (data[len - 1 - i] != pad_val) return 0;
    }
    return len - pad_val;
}


// -------------------------------------------------------------------------
// DER encoding/decoding for ECDSA signatures
// -------------------------------------------------------------------------
// micro-ecc gives us raw signatures: 64 bytes = r (32) || s (32).
// U2F expects DER-encoded signatures:
//   0x30 [total_len] 0x02 [r_len] [r_bytes] 0x02 [s_len] [s_bytes]
//
// The complication: DER integers are signed. If the high bit of r or s
// is set, we must prepend a 0x00 byte to indicate it's positive.
// This is why DER signatures vary between 70-72 bytes.

static size_t der_encode_integer(const uint8_t *val, size_t val_len, uint8_t *out) {
    // Skip leading zeros (DER integers are minimal)
    while (val_len > 1 && val[0] == 0x00) {
        val++;
        val_len--;
    }

    // If high bit is set, prepend 0x00 (positive sign)
    bool needs_pad = (val[0] & 0x80) != 0;

    size_t pos = 0;
    out[pos++] = 0x02;  // INTEGER tag
    out[pos++] = (uint8_t)(val_len + (needs_pad ? 1 : 0));
    if (needs_pad) {
        out[pos++] = 0x00;
    }
    memcpy(out + pos, val, val_len);
    pos += val_len;
    return pos;
}


static size_t raw_signature_to_der(const uint8_t *raw_sig, uint8_t *der_out) {
    // raw_sig is 64 bytes: r (32) || s (32)
    uint8_t r_buf[35], s_buf[35];  // max: tag(1) + len(1) + pad(1) + value(32)

    size_t r_len = der_encode_integer(raw_sig, 32, r_buf);
    size_t s_len = der_encode_integer(raw_sig + 32, 32, s_buf);

    // SEQUENCE wrapper
    der_out[0] = 0x30;  // SEQUENCE tag
    der_out[1] = (uint8_t)(r_len + s_len);
    memcpy(der_out + 2, r_buf, r_len);
    memcpy(der_out + 2 + r_len, s_buf, s_len);

    return 2 + r_len + s_len;
}


static bool der_decode_signature(const uint8_t *der, size_t der_len,
                                  uint8_t *raw_out) {
    // Parse DER back to raw 64 bytes for micro-ecc's verify.
    // We need this because U2F stores signatures in DER format,
    // but uECC_verify() expects raw (r||s).
    if (der_len < 8 || der[0] != 0x30) return false;

    size_t pos = 2;  // skip SEQUENCE tag + length

    // Parse r
    if (der[pos] != 0x02) return false;
    size_t r_len = der[pos + 1];
    pos += 2;
    // Skip leading zero padding
    const uint8_t *r_start = der + pos;
    if (r_len == 33 && r_start[0] == 0x00) { r_start++; r_len = 32; }
    // Copy right-aligned into 32 bytes (in case r is shorter than 32)
    memset(raw_out, 0, 32);
    memcpy(raw_out + (32 - r_len), r_start, r_len);
    pos += der[pos - 1];  // advance past r using original length

    // Parse s
    if (der[pos] != 0x02) return false;
    size_t s_len = der[pos + 1];
    pos += 2;
    const uint8_t *s_start = der + pos;
    if (s_len == 33 && s_start[0] == 0x00) { s_start++; s_len = 32; }
    memset(raw_out + 32, 0, 32);
    memcpy(raw_out + 32 + (32 - s_len), s_start, s_len);

    return true;
}


// -------------------------------------------------------------------------
// ECDSA key generation
// -------------------------------------------------------------------------

bool crypto_generate_keypair(uint8_t *public_key, uint8_t *private_key) {
    // micro-ecc produces a 64-byte public key (X||Y, no prefix).
    // FIDO needs 65 bytes (0x04||X||Y), so we write into public_key+1
    // and prepend the 0x04 byte.
    uint8_t raw_pub[RAW_PUBLIC_KEY_SIZE];

    DBG("GENERATE KEYPAIR (ECDSA P-256)\n");

    int ok = uECC_make_key(raw_pub, private_key, uECC_secp256r1());
    if (!ok) {
        printf("  ERROR: uECC_make_key failed!\n");
        return false;
    }

    // Add the 0x04 uncompressed point prefix
    public_key[0] = 0x04;
    memcpy(public_key + 1, raw_pub, RAW_PUBLIC_KEY_SIZE);

    DBG_HEX("Private key", private_key, PRIVATE_KEY_SIZE);
    DBG_HEX("Public key X", public_key + 1, 32);
    DBG_HEX("Public key Y", public_key + 33, 32);

    return true;
}


// -------------------------------------------------------------------------
// ECDSA signing
// -------------------------------------------------------------------------

bool crypto_sign(const uint8_t *private_key,
                 const uint8_t *data, size_t data_len,
                 uint8_t *signature, size_t *signature_len) {
    // Step 1: SHA-256 hash the data (same as Phase 1 — the Python
    // cryptography library did this internally with ECDSA(SHA256()))
    uint8_t hash[SHA256_SIZE];
    crypto_sha256(data, data_len, hash);

    DBG("ECDSA SIGN\n");
    DBG_HEX("Data hash (SHA-256)", hash, SHA256_SIZE);

    // Step 2: Sign the hash with micro-ecc → 64-byte raw signature
    uint8_t raw_sig[64];
    int ok = uECC_sign(private_key, hash, SHA256_SIZE, raw_sig, uECC_secp256r1());
    if (!ok) {
        printf("  ERROR: uECC_sign failed!\n");
        return false;
    }

    // Step 3: Convert raw (r||s) to DER format for U2F
    *signature_len = raw_signature_to_der(raw_sig, signature);

    DBG_HEX("Signature (DER)", signature, *signature_len);
    return true;
}


// -------------------------------------------------------------------------
// ECDSA verification
// -------------------------------------------------------------------------

bool crypto_verify(const uint8_t *public_key,
                   const uint8_t *data, size_t data_len,
                   const uint8_t *signature, size_t signature_len) {
    // Hash the data
    uint8_t hash[SHA256_SIZE];
    crypto_sha256(data, data_len, hash);

    // Decode DER signature back to raw (r||s) for micro-ecc
    uint8_t raw_sig[64];
    if (!der_decode_signature(signature, signature_len, raw_sig)) {
        DBG("  ERROR: DER decode failed\n");
        return false;
    }

    // micro-ecc wants the 64-byte raw public key (no 0x04 prefix)
    int ok = uECC_verify(public_key + 1, hash, SHA256_SIZE, raw_sig, uECC_secp256r1());
    return ok == 1;
}


// -------------------------------------------------------------------------
// Key wrapping — encrypt private key into a key handle
// -------------------------------------------------------------------------
// Format: [16 IV] [48 ciphertext] [32 HMAC] = 96 bytes
// Identical to Phase 1. Same labels, same format.

bool crypto_wrap_key(const uint8_t *master_secret,
                     const uint8_t *private_key,
                     uint8_t *key_handle) {
    DBG("WRAP KEY — encrypting private key into key handle\n");
    DBG_HEX("Private key (plaintext)", private_key, PRIVATE_KEY_SIZE);

    // Derive AES and HMAC keys
    uint8_t aes_key[32], hmac_key[32];
    derive_wrapping_keys(master_secret, aes_key, hmac_key);

    // Random IV
    uint8_t iv[AES_IV_SIZE];
    crypto_random(iv, AES_IV_SIZE);
    DBG_HEX("Random IV", iv, AES_IV_SIZE);

    // PKCS7 pad: 32 bytes → 48 bytes (adds full block of 0x10)
    uint8_t padded[48];
    size_t padded_len = pkcs7_pad(private_key, PRIVATE_KEY_SIZE, padded, sizeof(padded));
    if (padded_len == 0) return false;
    DBG("  After PKCS7 padding: %zu bytes\n", padded_len);

    // AES-256-CBC encrypt
    // mbedtls modifies the IV during encryption (it uses it as the running
    // CBC state), so we copy it first.
    uint8_t iv_copy[AES_IV_SIZE];
    memcpy(iv_copy, iv, AES_IV_SIZE);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aes_key, 256);

    uint8_t *ciphertext = key_handle + AES_IV_SIZE;  // write directly into key_handle
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len,
                           iv_copy, padded, ciphertext);
    mbedtls_aes_free(&aes);

    DBG_HEX("Ciphertext", ciphertext, padded_len);

    // Assemble key handle: [IV][ciphertext][HMAC]
    memcpy(key_handle, iv, AES_IV_SIZE);
    // ciphertext is already in place at key_handle + 16

    // HMAC over IV + ciphertext
    uint8_t hmac_input[AES_IV_SIZE + 48];
    memcpy(hmac_input, iv, AES_IV_SIZE);
    memcpy(hmac_input + AES_IV_SIZE, ciphertext, padded_len);

    uint8_t *tag = key_handle + AES_IV_SIZE + padded_len;
    hmac_sha256(hmac_key, 32, hmac_input, AES_IV_SIZE + padded_len, tag);

    DBG_HEX("HMAC tag", tag, HMAC_TAG_SIZE);
    DBG("  Key handle: [IV 16][ciphertext %zu][HMAC 32] = %d bytes\n",
        padded_len, KEY_HANDLE_SIZE);

    return true;
}


// -------------------------------------------------------------------------
// Key unwrapping — decrypt key handle back to private key
// -------------------------------------------------------------------------

bool crypto_unwrap_key(const uint8_t *master_secret,
                       const uint8_t *key_handle,
                       uint8_t *private_key) {
    DBG("UNWRAP KEY — decrypting key handle\n");

    // Split key handle into components
    const uint8_t *iv         = key_handle;
    const uint8_t *ciphertext = key_handle + AES_IV_SIZE;
    const uint8_t *tag        = key_handle + AES_IV_SIZE + 48;
    size_t ct_len = 48;  // PKCS7-padded 32 bytes

    DBG_HEX("IV", iv, AES_IV_SIZE);
    DBG_HEX("Ciphertext", ciphertext, ct_len);
    DBG_HEX("HMAC tag", tag, HMAC_TAG_SIZE);

    // Derive keys
    uint8_t aes_key[32], hmac_key[32];
    derive_wrapping_keys(master_secret, aes_key, hmac_key);

    // Verify HMAC first — authenticate-then-decrypt pattern
    uint8_t hmac_input[AES_IV_SIZE + 48];
    memcpy(hmac_input, iv, AES_IV_SIZE);
    memcpy(hmac_input + AES_IV_SIZE, ciphertext, ct_len);

    uint8_t expected_tag[HMAC_TAG_SIZE];
    hmac_sha256(hmac_key, 32, hmac_input, AES_IV_SIZE + ct_len, expected_tag);

    DBG_HEX("Expected HMAC", expected_tag, HMAC_TAG_SIZE);

    // Constant-time comparison to prevent timing attacks.
    // (On a personal device this doesn't matter much, but it's good practice.)
    uint8_t diff = 0;
    for (int i = 0; i < HMAC_TAG_SIZE; i++) {
        diff |= tag[i] ^ expected_tag[i];
    }
    if (diff != 0) {
        DBG("  HMAC MISMATCH — key handle rejected!\n");
        return false;
    }
    DBG("  HMAC MATCH — key handle is authentic\n");

    // Decrypt
    uint8_t iv_copy[AES_IV_SIZE];
    memcpy(iv_copy, iv, AES_IV_SIZE);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, aes_key, 256);  // Note: _dec for decryption

    uint8_t padded[48];
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ct_len,
                           iv_copy, ciphertext, padded);
    mbedtls_aes_free(&aes);

    // Remove PKCS7 padding
    size_t unpadded_len = pkcs7_unpad(padded, ct_len);
    if (unpadded_len != PRIVATE_KEY_SIZE) {
        DBG("  ERROR: unexpected unpadded length %zu (expected %d)\n",
            unpadded_len, PRIVATE_KEY_SIZE);
        return false;
    }

    memcpy(private_key, padded, PRIVATE_KEY_SIZE);
    DBG_HEX("Recovered private key", private_key, PRIVATE_KEY_SIZE);

    return true;
}
