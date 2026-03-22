#include "pico/stdlib.h"

// On most Pro Micro RP2040 boards, the onboard LED is on GPIO 25
// (same as the standard Pico). Some boards differ — check yours.
#define LED_PIN 25

int main() {
    // Initialize the SDK (sets up clocks, etc.)
    stdio_init_all();

    // Configure the LED pin — same concept as AVR's DDRx register,
    // but the SDK wraps it. Under the hood this sets the GPIO
    // function to SIO (software I/O) and direction to output.
    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);

    while (true) {
        gpio_put(LED_PIN, 1);    // Like PORTx |= (1 << pin) on AVR
        sleep_ms(250);
        gpio_put(LED_PIN, 0);
        sleep_ms(250);
    }
}
