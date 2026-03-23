#ifndef BUTTON_H
#define BUTTON_H

#include <stdbool.h>
#include <stdint.h>

// Wait for the BOOTSEL button to be pressed.
//
// While waiting, blinks the LED to signal "press the button" and calls
// on_tick() every ~200ms (used by the caller to send CTAPHID KEEPALIVEs
// so the host doesn't time out).
//
// Returns true if the button was pressed, false on timeout.
bool button_wait_for_press(uint32_t timeout_ms, void (*on_tick)(void));

#endif // BUTTON_H
