/**
 * Crypto test — exercises every function in crypto.c over serial.
 *
 * This is a temporary test harness, not the real authenticator.
 * Flash it, open a serial terminal, and watch the output.
 * Each test prints intermediate values so you can compare against
 * the Phase 1 Python verbose output.
 */

#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/time.h"
#include "crypto.h"

// Simple timing helper — returns elapsed microseconds
#define TIME_START() absolute_time_t _t0 = get_absolute_time()
#define TIME_MS()    ((double)absolute_time_diff_us(_t0, get_absolute_time()) / 1000.0)

// Pause between tests so you can read the output
static void wait_for_serial(void) {
    printf("\n  (Press Enter to continue...)\n");
    // Accept either \r or \n — different terminals send different line endings
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != '\r');
}

int main() {
    stdio_init_all();

    // Wait for USB serial to connect — without this, early printf
    // output is lost because the USB CDC device hasn't enumerated yet.
    // On AVR with hardware UART this wasn't needed, but USB serial
    // takes a moment to establish.
    sleep_ms(2000);

    printf("\n");
    printf("============================================================\n");
    printf("  FIDO U2F Authenticator — Crypto Module Test\n");
    printf("  Running on RP2040\n");
    printf("============================================================\n\n");

    // Initialize crypto (registers RNG with micro-ecc)
    crypto_init();

    // ------------------------------------------------------------------
    // Test 1: Random number generation
    // ------------------------------------------------------------------
    printf("\n--- TEST 1: Random Number Generation ---\n");
    uint8_t random_bytes[32];
    crypto_random(random_bytes, sizeof(random_bytes));
    crypto_print_hex("32 random bytes", random_bytes, 32);

    // Generate a second batch — should be different
    uint8_t random_bytes_2[32];
    crypto_random(random_bytes_2, sizeof(random_bytes_2));
    crypto_print_hex("32 more random bytes", random_bytes_2, 32);

    if (memcmp(random_bytes, random_bytes_2, 32) == 0) {
        printf("  WARNING: Two random batches are identical! RNG may be broken.\n");
    } else {
        printf("  OK — two batches differ (RNG is working)\n");
    }
    wait_for_serial();

    // ------------------------------------------------------------------
    // Test 2: SHA-256 hashing
    // ------------------------------------------------------------------
    printf("\n--- TEST 2: SHA-256 ---\n");

    // Known test vector: SHA-256("abc") = ba7816bf...
    const uint8_t abc[] = "abc";
    uint8_t hash[32];
    crypto_sha256(abc, 3, hash);
    crypto_print_hex("SHA-256(\"abc\")", hash, 32);

    const uint8_t expected_abc_hash[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    if (memcmp(hash, expected_abc_hash, 32) == 0) {
        printf("  PASS — matches known test vector\n");
    } else {
        printf("  FAIL — does not match!\n");
    }
    wait_for_serial();

    // ------------------------------------------------------------------
    // Test 3: ECDSA key generation
    // ------------------------------------------------------------------
    printf("\n--- TEST 3: ECDSA P-256 Key Generation ---\n");

    uint8_t public_key[PUBLIC_KEY_SIZE];
    uint8_t private_key[PRIVATE_KEY_SIZE];

    if (crypto_generate_keypair(public_key, private_key)) {
        printf("  PASS — keypair generated\n");
        printf("  Public key starts with 0x%02x (should be 0x04)\n", public_key[0]);
    } else {
        printf("  FAIL — key generation failed!\n");
    }
    wait_for_serial();

    // ------------------------------------------------------------------
    // Test 4: Sign and verify
    // ------------------------------------------------------------------
    printf("\n--- TEST 4: ECDSA Sign + Verify ---\n");

    const uint8_t message[] = "Hello from RP2040!";
    uint8_t signature[SIGNATURE_MAX_SIZE];
    size_t sig_len;

    if (crypto_sign(private_key, message, strlen((const char *)message),
                    signature, &sig_len)) {
        printf("  Signed %zu bytes of data → %zu byte DER signature\n",
               strlen((const char *)message), sig_len);

        // Verify with the matching public key — should pass
        bool valid = crypto_verify(public_key, message, strlen((const char *)message),
                                   signature, sig_len);
        printf("  Verify with correct key: %s\n", valid ? "PASS" : "FAIL");

        // Verify with wrong data — should fail
        const uint8_t wrong[] = "Wrong message!";
        bool invalid = crypto_verify(public_key, wrong, strlen((const char *)wrong),
                                     signature, sig_len);
        printf("  Verify with wrong data:  %s\n", invalid ? "FAIL (should be invalid!)" : "PASS (correctly rejected)");
    } else {
        printf("  FAIL — signing failed!\n");
    }
    wait_for_serial();

    // ------------------------------------------------------------------
    // Test 5: Key wrapping and unwrapping
    // ------------------------------------------------------------------
    printf("\n--- TEST 5: Key Wrap + Unwrap ---\n");

    // Generate a master secret (on real device this comes from flash)
    uint8_t master_secret[MASTER_SECRET_SIZE];
    crypto_random(master_secret, MASTER_SECRET_SIZE);
    crypto_print_hex("Master secret", master_secret, MASTER_SECRET_SIZE);

    // Wrap the private key from test 3
    uint8_t key_handle[KEY_HANDLE_SIZE];
    if (crypto_wrap_key(master_secret, private_key, key_handle)) {
        printf("  Wrapped into %d-byte key handle\n\n", KEY_HANDLE_SIZE);

        // Unwrap it back
        uint8_t recovered_key[PRIVATE_KEY_SIZE];
        if (crypto_unwrap_key(master_secret, key_handle, recovered_key)) {
            if (memcmp(private_key, recovered_key, PRIVATE_KEY_SIZE) == 0) {
                printf("  PASS — recovered key matches original!\n");
            } else {
                printf("  FAIL — recovered key differs from original!\n");
                crypto_print_hex("Original", private_key, PRIVATE_KEY_SIZE);
                crypto_print_hex("Recovered", recovered_key, PRIVATE_KEY_SIZE);
            }
        } else {
            printf("  FAIL — unwrap failed!\n");
        }
    } else {
        printf("  FAIL — wrap failed!\n");
    }
    wait_for_serial();

    // ------------------------------------------------------------------
    // Test 6: Unwrap with wrong master secret (should fail)
    // ------------------------------------------------------------------
    printf("\n--- TEST 6: Unwrap with Wrong Master Secret ---\n");

    uint8_t wrong_secret[MASTER_SECRET_SIZE];
    crypto_random(wrong_secret, MASTER_SECRET_SIZE);
    crypto_print_hex("Wrong secret", wrong_secret, MASTER_SECRET_SIZE);

    uint8_t dummy_key[PRIVATE_KEY_SIZE];
    bool should_fail = crypto_unwrap_key(wrong_secret, key_handle, dummy_key);
    printf("  Unwrap with wrong secret: %s\n",
           should_fail ? "FAIL (should have been rejected!)" : "PASS (correctly rejected)");

    // ------------------------------------------------------------------
    // Test 7: Full round-trip (generate → wrap → unwrap → sign → verify)
    // ------------------------------------------------------------------
    printf("\n--- TEST 7: Full Round-Trip ---\n");
    printf("  Simulating: registration then authentication\n\n");

    // Registration: generate keypair, wrap private key
    uint8_t reg_pub[PUBLIC_KEY_SIZE], reg_priv[PRIVATE_KEY_SIZE];
    uint8_t reg_handle[KEY_HANDLE_SIZE];
    crypto_generate_keypair(reg_pub, reg_priv);
    crypto_wrap_key(master_secret, reg_priv, reg_handle);

    printf("\n  --- (later, authenticating) ---\n\n");

    // Authentication: unwrap key handle, sign challenge
    uint8_t auth_priv[PRIVATE_KEY_SIZE];
    crypto_unwrap_key(master_secret, reg_handle, auth_priv);

    // Sign a challenge (simulated)
    uint8_t challenge[32];
    crypto_random(challenge, 32);
    crypto_print_hex("Challenge", challenge, 32);

    uint8_t auth_sig[SIGNATURE_MAX_SIZE];
    size_t auth_sig_len;
    crypto_sign(auth_priv, challenge, 32, auth_sig, &auth_sig_len);

    // Verify with the public key from registration
    bool round_trip_ok = crypto_verify(reg_pub, challenge, 32, auth_sig, auth_sig_len);
    printf("\n  Verify (pub from registration, sig from authentication): %s\n",
           round_trip_ok ? "PASS" : "FAIL");

    // ------------------------------------------------------------------
    // Test 8: Timing benchmarks
    // ------------------------------------------------------------------
    printf("\n--- TEST 8: Timing Benchmarks ---\n");
    printf("  Each operation measured individually.\n\n");

    // RNG: 32 bytes
    {
        uint8_t buf[32];
        TIME_START();
        crypto_random(buf, 32);
        printf("  RNG (32 bytes):       %7.2f ms\n", TIME_MS());
    }

    // SHA-256: 64 bytes
    {
        uint8_t buf[64], h[32];
        memset(buf, 0xAA, 64);
        TIME_START();
        crypto_sha256(buf, 64, h);
        printf("  SHA-256 (64 bytes):   %7.2f ms\n", TIME_MS());
    }

    // Key generation
    {
        uint8_t pub[PUBLIC_KEY_SIZE], priv[PRIVATE_KEY_SIZE];
        TIME_START();
        crypto_generate_keypair(pub, priv);
        printf("  Key generation:       %7.2f ms\n", TIME_MS());
    }

    // Signing
    {
        uint8_t sig[SIGNATURE_MAX_SIZE];
        size_t slen;
        uint8_t msg[32];
        memset(msg, 0xBB, 32);
        TIME_START();
        crypto_sign(private_key, msg, 32, sig, &slen);
        printf("  ECDSA sign:           %7.2f ms\n", TIME_MS());
    }

    // Verification
    {
        // First create a fresh signature to verify
        uint8_t sig[SIGNATURE_MAX_SIZE];
        size_t slen;
        uint8_t msg[32];
        memset(msg, 0xCC, 32);
        crypto_sign(private_key, msg, 32, sig, &slen);

        TIME_START();
        crypto_verify(public_key, msg, 32, sig, slen);
        printf("  ECDSA verify:         %7.2f ms\n", TIME_MS());
    }

    // Key wrap
    {
        uint8_t kh[KEY_HANDLE_SIZE];
        TIME_START();
        crypto_wrap_key(master_secret, private_key, kh);
        printf("  Key wrap:             %7.2f ms\n", TIME_MS());
    }

    // Key unwrap
    {
        uint8_t priv_out[PRIVATE_KEY_SIZE];
        TIME_START();
        crypto_unwrap_key(master_secret, key_handle, priv_out);
        printf("  Key unwrap:           %7.2f ms\n", TIME_MS());
    }

    // Full registration (keygen + wrap)
    {
        uint8_t p[PUBLIC_KEY_SIZE], k[PRIVATE_KEY_SIZE], kh[KEY_HANDLE_SIZE];
        TIME_START();
        crypto_generate_keypair(p, k);
        crypto_wrap_key(master_secret, k, kh);
        printf("  Full registration:    %7.2f ms\n", TIME_MS());
    }

    // Full authentication (unwrap + sign)
    {
        uint8_t priv_out[PRIVATE_KEY_SIZE];
        uint8_t sig[SIGNATURE_MAX_SIZE];
        size_t slen;
        uint8_t msg[32];
        memset(msg, 0xDD, 32);
        TIME_START();
        crypto_unwrap_key(master_secret, key_handle, priv_out);
        crypto_sign(priv_out, msg, 32, sig, &slen);
        printf("  Full authentication:  %7.2f ms\n", TIME_MS());
    }

    // ------------------------------------------------------------------
    // Done!
    // ------------------------------------------------------------------
    printf("\n============================================================\n");
    printf("  All crypto tests complete!\n");
    printf("============================================================\n");

    // Blink LED to indicate completion
    const uint pin = 25;
    gpio_init(pin);
    gpio_set_dir(pin, GPIO_OUT);
    while (true) {
        gpio_put(pin, 1);
        sleep_ms(100);
        gpio_put(pin, 0);
        sleep_ms(100);
    }
}
