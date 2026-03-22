/**
 * FIDO U2F Authenticator — RP2040 firmware.
 *
 * This will become the real authenticator. For now it's a placeholder
 * while we build and test individual modules.
 *
 * To run the crypto test instead, build the test_crypto target
 * (see CMakeLists.txt).
 */

#include <stdio.h>
#include "pico/stdlib.h"
#include "crypto.h"

int main() {
    stdio_init_all();
    sleep_ms(2000);

    printf("\n");
    printf("FIDO U2F Authenticator — RP2040\n");
    printf("Firmware placeholder. Build 'test_crypto' for crypto tests.\n");

    crypto_init();

    while (true) {
        tight_loop_contents();
    }
}
