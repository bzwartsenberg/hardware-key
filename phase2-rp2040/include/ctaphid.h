#ifndef CTAPHID_H
#define CTAPHID_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ---------------------------------------------------------------------------
// CTAPHID constants — defined by the FIDO HID protocol spec.
// These are identical to what we used in Phase 1's Python implementation.
// ---------------------------------------------------------------------------

#define CTAPHID_PACKET_SIZE     64      // Every packet is exactly 64 bytes
#define CTAPHID_INIT_PAYLOAD    57      // Payload bytes in an initialization packet
#define CTAPHID_CONT_PAYLOAD    59      // Payload bytes in a continuation packet

// Commands — high bit (0x80) marks initialization packets
#define CTAPHID_INIT        (0x80 | 0x06)   // Channel allocation handshake
#define CTAPHID_MSG         (0x80 | 0x03)   // Carry a U2F message
#define CTAPHID_ERROR       (0x80 | 0x3F)   // Error response
#define CTAPHID_KEEPALIVE   (0x80 | 0x3B)   // "I'm still working"

// The broadcast channel — clients send INIT here before they have a channel
#define BROADCAST_CID       0xFFFFFFFF

// Error codes
#define ERR_INVALID_CMD     0x01
#define ERR_INVALID_LEN     0x03
#define ERR_INVALID_CHANNEL 0x0B
#define ERR_OTHER           0x7F

// Maximum payload we'll reassemble. Register responses can be ~524 bytes,
// so 600 gives comfortable headroom.
#define CTAPHID_MAX_PAYLOAD 600

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// A fully reassembled CTAPHID message (one or more packets combined).
typedef struct {
    uint32_t cid;
    uint8_t  cmd;
    uint16_t length;
    uint8_t  payload[CTAPHID_MAX_PAYLOAD];
} ctaphid_message_t;

// Callback type for sending a single 64-byte packet.
// main.c provides this — it writes 64 raw bytes to USB serial.
typedef void (*ctaphid_send_fn)(const uint8_t *packet);

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

// Reset CTAPHID state (channel counter, reassembly buffer).
void ctaphid_init(void);

// Feed a raw 64-byte packet. Returns true when a complete message has been
// reassembled and is ready to read via ctaphid_get_message().
bool ctaphid_receive_packet(const uint8_t *packet);

// Get the last fully reassembled message. Only valid after
// ctaphid_receive_packet() returned true.
const ctaphid_message_t *ctaphid_get_message(void);

// Handle the CTAPHID_INIT command (channel allocation handshake).
// Writes 17 bytes of response payload into response_buf.
// Returns the channel ID to use in the response.
uint32_t ctaphid_handle_init(uint32_t cid, const uint8_t *nonce,
                             uint8_t *response_buf);

// Build and send a response. Splits payload across init + continuation
// packets as needed, calling send_fn for each 64-byte packet.
void ctaphid_send_response(uint32_t cid, uint8_t cmd,
                           const uint8_t *payload, size_t payload_len,
                           ctaphid_send_fn send_fn);

// Send an error response (single packet).
void ctaphid_send_error(uint32_t cid, uint8_t error_code,
                        ctaphid_send_fn send_fn);

#endif // CTAPHID_H
