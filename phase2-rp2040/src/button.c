/**
 * User presence via the BOOTSEL button.
 *
 * The BOOTSEL button on the RP2040 is special — it's not a regular GPIO.
 * It's wired to the flash chip's CS (chip select) pin on the QSPI bus.
 * Normally this pin is controlled by the flash interface, but we can
 * temporarily reconfigure it as an input to read the button state.
 *
 * The catch: while we're reading the CS pin, the flash chip is
 * deselected, so code can't execute from flash. That's why
 * get_bootsel_button() must run entirely from RAM — hence the
 * __no_inline_not_in_flash_func attribute, which tells the linker
 * to place this function in RAM instead of flash.
 */

#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/sio.h"
#include "button.h"

#define LED_PIN 25

// ---------------------------------------------------------------------------
// BOOTSEL button reading — must be in RAM
// ---------------------------------------------------------------------------

static bool __no_inline_not_in_flash_func(get_bootsel_button)(void) {
    // The BOOTSEL button pulls the QSPI CS pin low when pressed.
    // To read it, we:
    //   1. Disable interrupts (can't run ISRs from flash)
    //   2. Override the CS pin output to low (so the flash chip stays
    //      deselected regardless of button state)
    //   3. Read the input value of the CS pin
    //   4. Restore everything

    const uint CS_PIN_INDEX = 1;  // QSPI_SS is GPIO_QSPI pin 1

    uint32_t flags = save_and_disable_interrupts();

    // Drive CS low so flash ignores us, then read the actual pin state
    hw_write_masked(
        &ioqspi_hw->io[CS_PIN_INDEX].ctrl,
        GPIO_OVERRIDE_LOW << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
        IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS
    );

    // Small delay for the pin state to settle
    for (volatile int i = 0; i < 1000; i++);

    // Read the input — button pressed = pin pulled low = bit clear
    bool pressed = !(sio_hw->gpio_hi_in & (1u << CS_PIN_INDEX));

    // Restore normal CS operation
    hw_write_masked(
        &ioqspi_hw->io[CS_PIN_INDEX].ctrl,
        GPIO_OVERRIDE_NORMAL << IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_LSB,
        IO_QSPI_GPIO_QSPI_SS_CTRL_OEOVER_BITS
    );

    restore_interrupts(flags);

    return pressed;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool button_wait_for_press(uint32_t timeout_ms, void (*on_tick)(void)) {
    absolute_time_t deadline = make_timeout_time_ms(timeout_ms);
    absolute_time_t next_tick = get_absolute_time();
    bool led_state = false;

    while (!time_reached(deadline)) {
        // Check button with simple debounce: require two consecutive reads
        if (get_bootsel_button()) {
            sleep_ms(20);
            if (get_bootsel_button()) {
                gpio_put(LED_PIN, 0);
                return true;
            }
        }

        // Every ~200ms: toggle LED and call the tick callback
        if (time_reached(next_tick)) {
            led_state = !led_state;
            gpio_put(LED_PIN, led_state);

            if (on_tick) {
                on_tick();
            }

            next_tick = make_timeout_time_ms(200);
        }

        sleep_ms(10);
    }

    gpio_put(LED_PIN, 0);
    return false;
}
