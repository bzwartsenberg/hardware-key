/**
 * CTAPHID transport layer — packet framing and channel management.
 *
 * This is the C port of Phase 1's CTAPHIDLayer class. It handles:
 * - Parsing 64-byte packets (init + continuation)
 * - Reassembling multi-packet messages
 * - Building multi-packet responses
 * - Channel allocation (INIT command)
 *
 * Packet format (initialization):
 *   Bytes 0-3:  Channel ID (big-endian uint32)
 *   Byte 4:     Command (high bit set)
 *   Bytes 5-6:  Total payload length (big-endian uint16)
 *   Bytes 7-63: First 57 bytes of payload
 *
 * Packet format (continuation):
 *   Bytes 0-3:  Channel ID
 *   Byte 4:     Sequence number (0, 1, 2... — high bit clear)
 *   Bytes 5-63: Next 59 bytes of payload
 */

#include <string.h>
#include "ctaphid.h"

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

static uint32_t next_cid;              // Next channel ID to assign
static ctaphid_message_t pending_msg;  // Message being reassembled
static bool reassembling;              // True if we're mid-reassembly
static size_t received_so_far;         // Bytes received for pending message
static ctaphid_message_t complete_msg; // Last fully reassembled message

// ---------------------------------------------------------------------------
// Helpers — big-endian encoding/decoding
// ---------------------------------------------------------------------------

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint16_t read_be16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static void write_be32(uint8_t *p, uint32_t val) {
    p[0] = (uint8_t)(val >> 24);
    p[1] = (uint8_t)(val >> 16);
    p[2] = (uint8_t)(val >> 8);
    p[3] = (uint8_t)val;
}

static void write_be16(uint8_t *p, uint16_t val) {
    p[0] = (uint8_t)(val >> 8);
    p[1] = (uint8_t)val;
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

void ctaphid_init(void) {
    next_cid = 1;
    reassembling = false;
    received_so_far = 0;
    memset(&pending_msg, 0, sizeof(pending_msg));
    memset(&complete_msg, 0, sizeof(complete_msg));
}

// ---------------------------------------------------------------------------
// Packet reception and reassembly
// ---------------------------------------------------------------------------

bool ctaphid_receive_packet(const uint8_t *packet) {
    uint32_t cid = read_be32(packet);
    bool is_init = (packet[4] & 0x80) != 0;

    if (is_init) {
        // Initialization packet — start of a new message
        uint8_t cmd = packet[4];
        uint16_t total_len = read_be16(packet + 5);

        // How much payload is in this first packet
        size_t chunk = (total_len < CTAPHID_INIT_PAYLOAD)
                     ? total_len : CTAPHID_INIT_PAYLOAD;

        if (total_len > CTAPHID_MAX_PAYLOAD) {
            // Message too large — drop it
            reassembling = false;
            return false;
        }

        pending_msg.cid = cid;
        pending_msg.cmd = cmd;
        pending_msg.length = total_len;
        memcpy(pending_msg.payload, packet + 7, chunk);
        received_so_far = chunk;

        if (received_so_far >= total_len) {
            // Complete in one packet
            memcpy(&complete_msg, &pending_msg, sizeof(complete_msg));
            reassembling = false;
            return true;
        }

        // Need continuation packets
        reassembling = true;
        return false;

    } else {
        // Continuation packet
        if (!reassembling || cid != pending_msg.cid) {
            return false;  // No pending message for this channel
        }

        size_t remaining = pending_msg.length - received_so_far;
        size_t chunk = (remaining < CTAPHID_CONT_PAYLOAD)
                     ? remaining : CTAPHID_CONT_PAYLOAD;

        memcpy(pending_msg.payload + received_so_far, packet + 5, chunk);
        received_so_far += chunk;

        if (received_so_far >= pending_msg.length) {
            // Message complete
            memcpy(&complete_msg, &pending_msg, sizeof(complete_msg));
            reassembling = false;
            return true;
        }

        return false;  // Still waiting for more
    }
}

const ctaphid_message_t *ctaphid_get_message(void) {
    return &complete_msg;
}

// ---------------------------------------------------------------------------
// INIT command — channel allocation
// ---------------------------------------------------------------------------

uint32_t ctaphid_handle_init(uint32_t cid, const uint8_t *nonce,
                             uint8_t *response_buf) {
    // Response format (17 bytes):
    //   Bytes 0-7:   Client's nonce (echoed back)
    //   Bytes 8-11:  New channel ID
    //   Byte 12:     Protocol version (2)
    //   Byte 13:     Major device version
    //   Byte 14:     Minor device version
    //   Byte 15:     Build device version
    //   Byte 16:     Capabilities (0 = U2F only, no CBOR/CTAP2)

    uint32_t new_cid = next_cid++;

    memcpy(response_buf, nonce, 8);
    write_be32(response_buf + 8, new_cid);
    response_buf[12] = 2;    // CTAPHID protocol version
    response_buf[13] = 0;    // Device major
    response_buf[14] = 0;    // Device minor
    response_buf[15] = 1;    // Device build
    response_buf[16] = 0x00; // Capabilities: no CBOR, no NMSG

    // Response goes to broadcast CID if that's what the client used
    return (cid == BROADCAST_CID) ? BROADCAST_CID : cid;
}

// ---------------------------------------------------------------------------
// Response building — splits payload across packets
// ---------------------------------------------------------------------------

void ctaphid_send_response(uint32_t cid, uint8_t cmd,
                           const uint8_t *payload, size_t payload_len,
                           ctaphid_send_fn send_fn) {
    uint8_t packet[CTAPHID_PACKET_SIZE];

    // --- First packet (initialization) ---
    memset(packet, 0, CTAPHID_PACKET_SIZE);
    write_be32(packet, cid);
    packet[4] = cmd;
    write_be16(packet + 5, (uint16_t)payload_len);

    size_t chunk = (payload_len < CTAPHID_INIT_PAYLOAD)
                 ? payload_len : CTAPHID_INIT_PAYLOAD;
    memcpy(packet + 7, payload, chunk);
    send_fn(packet);

    // --- Continuation packets ---
    size_t offset = chunk;
    uint8_t seq = 0;

    while (offset < payload_len) {
        memset(packet, 0, CTAPHID_PACKET_SIZE);
        write_be32(packet, cid);
        packet[4] = seq++;

        size_t remaining = payload_len - offset;
        chunk = (remaining < CTAPHID_CONT_PAYLOAD)
              ? remaining : CTAPHID_CONT_PAYLOAD;
        memcpy(packet + 5, payload + offset, chunk);
        send_fn(packet);

        offset += chunk;
    }
}

void ctaphid_send_error(uint32_t cid, uint8_t error_code,
                        ctaphid_send_fn send_fn) {
    ctaphid_send_response(cid, CTAPHID_ERROR, &error_code, 1, send_fn);
}
