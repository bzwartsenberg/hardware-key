/**
 * FIDO U2F Authenticator — RP2040 firmware.
 *
 * Main loop: reads 64-byte CTAPHID packets from USB serial, processes
 * them through the CTAPHID and U2F layers, and sends responses back.
 *
 * The serial port carries raw binary packets (no text, no debug output).
 * A Python serial bridge (bridge/serial_bridge.py) sits between this
 * firmware and the test clients, translating UDP <-> serial.
 *
 * Build targets (see CMakeLists.txt):
 *   make authenticator   — this firmware
 *   make test_crypto     — crypto test with benchmarks
 */

#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "crypto.h"
#include "ctaphid.h"
#include "u2f.h"

// LED on GPIO 25 (Pro Micro RP2040) — blink to show activity
#define LED_PIN 25

// ---------------------------------------------------------------------------
// Serial I/O — raw binary, no text
// ---------------------------------------------------------------------------
// CTAPHID packets are always exactly 64 bytes. Both sides know this,
// so no framing protocol is needed — just read/write 64 bytes at a time.

static void read_packet(uint8_t *buf) {
    for (int i = 0; i < CTAPHID_PACKET_SIZE; i++) {
        buf[i] = (uint8_t)getchar();
    }
}

static void send_packet(const uint8_t *buf) {
    for (int i = 0; i < CTAPHID_PACKET_SIZE; i++) {
        putchar_raw(buf[i]);
    }
    stdio_flush();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    stdio_init_all();

    // LED setup — we'll blink it on each packet to show the device is alive
    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);

    // Wait for USB serial to enumerate. The host (serial bridge) needs
    // time to open the port.
    sleep_ms(1000);

    // Initialize subsystems
    crypto_init();
    ctaphid_init();
    u2f_init();

    // Blink LED twice to signal "ready"
    for (int i = 0; i < 2; i++) {
        gpio_put(LED_PIN, 1);
        sleep_ms(100);
        gpio_put(LED_PIN, 0);
        sleep_ms(100);
    }

    // Main packet loop — runs forever
    uint8_t packet[CTAPHID_PACKET_SIZE];

    while (true) {
        // Read one 64-byte packet (blocks until data arrives)
        read_packet(packet);

        // Toggle LED to show activity
        gpio_put(LED_PIN, 1);

        // Feed packet to CTAPHID for reassembly
        if (!ctaphid_receive_packet(packet)) {
            // Need more packets (continuation) — keep reading
            gpio_put(LED_PIN, 0);
            continue;
        }

        // Complete message received — dispatch
        const ctaphid_message_t *msg = ctaphid_get_message();

        if (msg->cmd == CTAPHID_INIT) {
            // Channel allocation handshake
            uint8_t init_response[17];
            uint32_t resp_cid = ctaphid_handle_init(
                msg->cid, msg->payload, init_response);
            ctaphid_send_response(resp_cid, CTAPHID_INIT,
                                  init_response, 17, send_packet);

        } else if (msg->cmd == CTAPHID_MSG) {
            // U2F message — pass to U2F layer
            uint8_t response[U2F_MAX_RESPONSE];
            size_t resp_len = u2f_handle_message(
                msg->payload, msg->length, response);
            ctaphid_send_response(msg->cid, CTAPHID_MSG,
                                  response, resp_len, send_packet);

        } else {
            // Unknown command
            ctaphid_send_error(msg->cid, ERR_INVALID_CMD, send_packet);
        }

        gpio_put(LED_PIN, 0);
    }
}
