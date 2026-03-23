#ifndef U2F_H
#define U2F_H

#include <stdint.h>
#include <stddef.h>

// ---------------------------------------------------------------------------
// U2F constants — same values as Phase 1.
// These come from the FIDO U2F spec and are based on ISO 7816 APDU framing.
// ---------------------------------------------------------------------------

// Command bytes (INS field in the APDU)
#define U2F_REGISTER        0x01    // "Make me a new credential"
#define U2F_AUTHENTICATE    0x02    // "Sign this challenge"
#define U2F_VERSION         0x03    // "What version are you?"

// Authentication control bytes (P1 field)
#define AUTH_ENFORCE         0x03   // Normal auth — require user presence
#define AUTH_CHECK           0x07   // Just check if key handle is ours

// U2F status codes — appended as 2 bytes to every response
#define SW_NO_ERROR                 0x9000
#define SW_CONDITIONS_NOT_SATISFIED 0x6985  // User not present, or check-only "yes"
#define SW_WRONG_DATA               0x6A80  // Bad key handle
#define SW_INS_NOT_SUPPORTED        0x6D00  // Unknown command

// Maximum response size (register response is the largest)
#define U2F_MAX_RESPONSE    600

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

// Initialize the U2F layer: generate master secret, attestation keypair,
// and self-signed attestation certificate. Call once at startup after
// crypto_init().
void u2f_init(void);

// Handle a complete U2F APDU message (the payload from a CTAPHID_MSG).
// Writes the response into response_buf and returns the response length.
size_t u2f_handle_message(const uint8_t *data, size_t data_len,
                          uint8_t *response_buf);

#endif // U2F_H
