/**
 * FIDO U2F Authenticator — RP2040 firmware.
 *
 * Main loop: processes 64-byte CTAPHID packets received as USB HID reports,
 * dispatches them through the CTAPHID and U2F layers, and sends responses
 * back as HID reports.
 *
 * The device presents as a FIDO U2F HID authenticator (usage page 0xF1D0).
 * Browsers and OS WebAuthn APIs talk to it directly — no serial bridge needed.
 *
 * USB stack: TinyUSB (bundled with Pico SDK). Descriptors in usb_descriptors.c.
 */

#include <string.h>
#include "pico/stdlib.h"
#include "bsp/board.h"
#include "tusb.h"
#include "crypto.h"
#include "ctaphid.h"
#include "u2f.h"
#include "storage.h"

#define LED_PIN 25

// ---------------------------------------------------------------------------
// HID packet buffer — shared with usb_descriptors.c
// ---------------------------------------------------------------------------
// When TinyUSB receives a 64-byte HID report on the OUT endpoint, it calls
// tud_hid_set_report_cb() in usb_descriptors.c, which copies the data here
// and sets the flag. We check the flag in our main loop.
//
// "volatile" because it's written from a callback and read from main loop.
// On the RP2040 in polled mode (no USB interrupts), this isn't strictly
// necessary — both run on the same core — but it's good practice and
// prevents the compiler from optimizing away the flag check.

volatile bool hid_packet_received = false;
uint8_t hid_packet_buf[64];

// ---------------------------------------------------------------------------
// Sending packets — now via HID instead of serial
// ---------------------------------------------------------------------------

static void send_packet(const uint8_t *buf) {
    // Wait for the IN endpoint to be ready. This blocks until the host
    // has picked up the previous report. tud_task() processes USB events
    // while we wait — without it, tud_hid_ready() would never become true.
    //
    // In practice this is very fast: the host polls every 5ms (our
    // descriptor's bInterval), so we wait at most 5ms between packets.
    while (!tud_hid_ready()) {
        tud_task();
    }

    // Send a 64-byte HID report. report_id=0 because our report descriptor
    // doesn't use report IDs (there's only one report format).
    tud_hid_report(0, buf, CTAPHID_PACKET_SIZE);
}

// ---------------------------------------------------------------------------
// Keepalive — sent while waiting for user presence (button press)
// ---------------------------------------------------------------------------
// Same design as the serial version: we set active_cid before calling
// u2f_handle_message, and the keepalive callback sends a CTAPHID_KEEPALIVE
// packet on that channel every ~200ms during button_wait_for_press.
//
// One important difference from serial: we MUST call tud_task() regularly
// to keep the USB stack alive. If we stop calling it for too long, the host
// might think we've disconnected. We call it here (runs every ~200ms from
// the button loop), and also in send_packet's wait loop.

static uint32_t active_cid;

static void send_keepalive(void) {
    tud_task();  // Keep USB alive during button wait

    uint8_t status = 0x02;  // STATUS_UPNEEDED
    ctaphid_send_response(active_cid, CTAPHID_KEEPALIVE,
                          &status, 1, send_packet);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    // board_init() is a TinyUSB function that initializes the board:
    // clocks, GPIO, and USB PHY. This replaces stdio_init_all() from the
    // serial version — we're managing USB ourselves now, not through stdio.
    board_init();

    // Initialize the TinyUSB device stack. After this call, TinyUSB will
    // respond to USB enumeration — the host sees a new device appear.
    // But we still need to call tud_task() regularly to process events.
    tusb_init();

    // LED setup
    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);

    // Initialize subsystems — same order as before
    crypto_init();
    storage_init();
    ctaphid_init();
    u2f_init();

    // Blink LED twice to signal "ready"
    // (No serial output possible now — LED is our only debug signal)
    for (int i = 0; i < 2; i++) {
        gpio_put(LED_PIN, 1);
        sleep_ms(100);
        gpio_put(LED_PIN, 0);
        sleep_ms(100);
    }

    // Main loop — runs forever
    while (true) {
        // Process USB events. This is the heartbeat of the USB stack:
        // it handles enumeration, endpoint transfers, and triggers our
        // callbacks (like tud_hid_set_report_cb when a packet arrives).
        // Must be called frequently — at least every few ms.
        tud_task();

        // Check if a packet arrived (flag set by tud_hid_set_report_cb)
        if (!hid_packet_received) {
            continue;
        }

        // Clear the flag and copy the packet (buffer could be overwritten
        // by next tud_task if another packet arrives quickly)
        hid_packet_received = false;
        uint8_t packet[CTAPHID_PACKET_SIZE];
        memcpy(packet, hid_packet_buf, CTAPHID_PACKET_SIZE);

        // Toggle LED to show activity
        gpio_put(LED_PIN, 1);

        // Feed packet to CTAPHID for reassembly
        if (!ctaphid_receive_packet(packet)) {
            gpio_put(LED_PIN, 0);
            continue;
        }

        // Complete message received — dispatch
        const ctaphid_message_t *msg = ctaphid_get_message();

        if (msg->cmd == CTAPHID_INIT) {
            uint8_t init_response[17];
            uint32_t resp_cid = ctaphid_handle_init(
                msg->cid, msg->payload, init_response);
            ctaphid_send_response(resp_cid, CTAPHID_INIT,
                                  init_response, 17, send_packet);

        } else if (msg->cmd == CTAPHID_MSG) {
            active_cid = msg->cid;
            uint8_t response[U2F_MAX_RESPONSE];
            size_t resp_len = u2f_handle_message(
                msg->payload, msg->length, response, send_keepalive);
            ctaphid_send_response(msg->cid, CTAPHID_MSG,
                                  response, resp_len, send_packet);

        } else {
            ctaphid_send_error(msg->cid, ERR_INVALID_CMD, send_packet);
        }

        gpio_put(LED_PIN, 0);
    }
}
