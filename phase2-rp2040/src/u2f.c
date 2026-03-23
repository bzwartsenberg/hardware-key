/**
 * U2F application layer — Register, Authenticate, and Version commands.
 *
 * This is the C port of Phase 1's U2FAuthenticator class. It handles
 * the U2F protocol logic: creating credentials (Register), proving
 * ownership of credentials (Authenticate), and reporting the version.
 *
 * The most interesting new piece here is the self-signed X.509 attestation
 * certificate, which we build from raw DER bytes. In Phase 1, Python's
 * cryptography library handled this. Here we construct the ASN.1/DER
 * encoding by hand — a good exercise in understanding what X.509
 * certificates actually look like at the byte level.
 */

#include <string.h>
#include <stdio.h>
#include "u2f.h"
#include "crypto.h"

// ---------------------------------------------------------------------------
// State — persists across requests (until reboot)
// ---------------------------------------------------------------------------

static uint8_t master_secret[MASTER_SECRET_SIZE];
static uint8_t attestation_privkey[PRIVATE_KEY_SIZE];
static uint8_t attestation_cert[400];  // DER-encoded X.509 cert
static size_t  attestation_cert_len;
static uint32_t sign_counter;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Write a big-endian uint16 status code.
static size_t write_status(uint8_t *buf, uint16_t sw) {
    buf[0] = (uint8_t)(sw >> 8);
    buf[1] = (uint8_t)sw;
    return 2;
}

// Write a big-endian uint32.
static void write_be32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val >> 24);
    buf[1] = (uint8_t)(val >> 16);
    buf[2] = (uint8_t)(val >> 8);
    buf[3] = (uint8_t)val;
}

// ---------------------------------------------------------------------------
// X.509 Attestation Certificate — DER encoding from scratch
// ---------------------------------------------------------------------------
//
// During registration, the authenticator must include an attestation
// certificate in the response. This certificate binds the attestation
// public key to the device identity. For real devices (YubiKeys etc.),
// the cert chains to the manufacturer's root CA. Ours is self-signed.
//
// X.509 certificates use ASN.1 DER encoding. DER is a tag-length-value
// format where:
//   - Tag: 1 byte identifying the type (SEQUENCE=0x30, INTEGER=0x02, etc.)
//   - Length: 1+ bytes (short form if <128, long form otherwise)
//   - Value: the actual content
//
// A certificate has this structure:
//   SEQUENCE {
//     TBSCertificate    -- the part that gets signed
//     SignatureAlgorithm
//     SignatureValue
//   }
//
// We build the TBS (To Be Signed) certificate from a template that has
// everything pre-computed except the 65-byte public key. At runtime we:
//   1. Copy the template and insert the public key
//   2. Wrap it in a SEQUENCE tag → complete TBS
//   3. SHA-256 hash the TBS, sign with ECDSA → signature
//   4. Assemble the outer Certificate SEQUENCE

// TBS certificate content (everything inside the TBS SEQUENCE).
// The only variable part is the 65-byte public key at the very end.
// Total: 128 bytes of fixed template + 65 bytes of public key = 193 bytes.
static const uint8_t tbs_content_prefix[] = {
    // Version: [0] EXPLICIT INTEGER 2 (v3)
    0xa0, 0x03, 0x02, 0x01, 0x02,

    // Serial Number: INTEGER 1
    0x02, 0x01, 0x01,

    // Signature Algorithm: ecdsa-with-SHA256 (OID 1.2.840.10045.4.3.2)
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,

    // Issuer: CN=DIY FIDO Key
    0x30, 0x17, 0x31, 0x15, 0x30, 0x13,
    0x06, 0x03, 0x55, 0x04, 0x03,               // OID: commonName
    0x0c, 0x0c,                                   // UTF8String, 12 bytes
    'D','I','Y',' ','F','I','D','O',' ','K','e','y',

    // Validity: 2025-01-01 to 2035-01-01
    0x30, 0x1e,
    0x17, 0x0d, '2','5','0','1','0','1','0','0','0','0','0','0','Z',
    0x17, 0x0d, '3','5','0','1','0','1','0','0','0','0','0','0','Z',

    // Subject: CN=DIY FIDO Key (same as issuer — self-signed)
    0x30, 0x17, 0x31, 0x15, 0x30, 0x13,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0c,
    'D','I','Y',' ','F','I','D','O',' ','K','e','y',

    // SubjectPublicKeyInfo prefix:
    //   SEQUENCE { SEQUENCE { ecPublicKey, prime256v1 }, BIT STRING ... }
    0x30, 0x59,                                   // SPKI SEQUENCE (89 bytes)
    0x30, 0x13,                                   // Algorithm SEQUENCE (19 bytes)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,  // OID ecPublicKey
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,  // OID prime256v1
    0x03, 0x42, 0x00,                             // BIT STRING (66 bytes, 0 unused bits)
    // [65 bytes of public key follow: 0x04 || X(32) || Y(32)]
};

// Signature algorithm identifier (used twice: in TBS and in outer cert)
static const uint8_t sig_algo_der[] = {
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
};

// Build the self-signed attestation certificate.
// Writes DER-encoded cert into cert_buf and returns its length.
static size_t build_attestation_cert(const uint8_t *pubkey_65,
                                     const uint8_t *privkey_32,
                                     uint8_t *cert_buf) {
    // --- Step 1: Build TBS certificate ---
    // TBS content = prefix (128 bytes) + public key (65 bytes) = 193 bytes
    // TBS SEQUENCE = tag(1) + length(2) + content(193) = 196 bytes
    // (193 = 0xC1, needs long-form length: 0x81 0xC1)

    uint8_t tbs[196];
    tbs[0] = 0x30;       // SEQUENCE tag
    tbs[1] = 0x81;       // Long-form length, 1 byte follows
    tbs[2] = 0xc1;       // 193 = content length
    memcpy(tbs + 3, tbs_content_prefix, sizeof(tbs_content_prefix));
    memcpy(tbs + 3 + sizeof(tbs_content_prefix), pubkey_65, 65);

    // --- Step 2: Sign the TBS ---
    // crypto_sign hashes with SHA-256 then signs with ECDSA — exactly
    // what ecdsa-with-SHA256 specifies.
    uint8_t sig_der[SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;
    crypto_sign(privkey_32, tbs, sizeof(tbs), sig_der, &sig_len);

    // --- Step 3: Assemble the outer Certificate SEQUENCE ---
    // Content = TBS(196) + sigAlgo(12) + BIT STRING(3 + sig_len)
    size_t bitstring_content_len = 1 + sig_len;  // unused-bits byte + signature
    size_t outer_content_len = sizeof(tbs) + sizeof(sig_algo_der)
                             + 1 + 1 + bitstring_content_len;
    //                         ^tag ^len (bitstring content < 128? not always)

    // BIT STRING length encoding
    // sig_len is 70-72, so bitstring_content_len is 71-73, which is < 128
    // → single-byte length

    // Outer SEQUENCE length: 196 + 12 + 2 + 1 + sig_len
    // = 211 + sig_len ≈ 281-283, which is > 255
    // → needs 3-byte length encoding: 0x82 [high] [low]
    size_t total_content = sizeof(tbs) + sizeof(sig_algo_der)
                         + 1 + 1 + bitstring_content_len;
    // Correction: BIT STRING total = tag(1) + length_bytes + content
    // content = 1 (unused bits) + sig_len
    // If content < 128: length_bytes = 1
    // If content >= 128: length_bytes = 2 (0x81 + len)
    size_t bs_overhead;
    if (bitstring_content_len < 128) {
        bs_overhead = 1 + 1;  // tag + 1-byte length
    } else {
        bs_overhead = 1 + 2;  // tag + 0x81 + length byte
    }
    total_content = sizeof(tbs) + sizeof(sig_algo_der)
                  + bs_overhead + bitstring_content_len;

    size_t pos = 0;

    // Outer SEQUENCE tag + length
    cert_buf[pos++] = 0x30;
    if (total_content < 128) {
        cert_buf[pos++] = (uint8_t)total_content;
    } else if (total_content < 256) {
        cert_buf[pos++] = 0x81;
        cert_buf[pos++] = (uint8_t)total_content;
    } else {
        cert_buf[pos++] = 0x82;
        cert_buf[pos++] = (uint8_t)(total_content >> 8);
        cert_buf[pos++] = (uint8_t)total_content;
    }

    // TBS certificate
    memcpy(cert_buf + pos, tbs, sizeof(tbs));
    pos += sizeof(tbs);

    // Signature algorithm
    memcpy(cert_buf + pos, sig_algo_der, sizeof(sig_algo_der));
    pos += sizeof(sig_algo_der);

    // Signature as BIT STRING
    cert_buf[pos++] = 0x03;  // BIT STRING tag
    if (bitstring_content_len < 128) {
        cert_buf[pos++] = (uint8_t)bitstring_content_len;
    } else {
        cert_buf[pos++] = 0x81;
        cert_buf[pos++] = (uint8_t)bitstring_content_len;
    }
    cert_buf[pos++] = 0x00;  // No unused bits
    memcpy(cert_buf + pos, sig_der, sig_len);
    pos += sig_len;

    return pos;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

void u2f_init(void) {
    // Generate master secret — root of all key wrapping.
    // On a real device this would be read from flash (written once at
    // first boot). Here it's fresh each boot, like Phase 1.
    crypto_random(master_secret, MASTER_SECRET_SIZE);

    // Generate attestation keypair and self-signed certificate.
    // On a real device the attestation key is burned in during
    // manufacturing. We generate it each boot.
    uint8_t attestation_pubkey[PUBLIC_KEY_SIZE];
    crypto_generate_keypair(attestation_pubkey, attestation_privkey);
    attestation_cert_len = build_attestation_cert(
        attestation_pubkey, attestation_privkey, attestation_cert);

    sign_counter = 0;
}

// ---------------------------------------------------------------------------
// U2F_VERSION — return "U2F_V2"
// ---------------------------------------------------------------------------

static size_t handle_version(uint8_t *response) {
    memcpy(response, "U2F_V2", 6);
    write_status(response + 6, SW_NO_ERROR);
    return 8;
}

// ---------------------------------------------------------------------------
// U2F_REGISTER — create a new credential
// ---------------------------------------------------------------------------
//
// Input (64 bytes):
//   challenge_param (32) + app_param (32)
//
// Output:
//   0x05 | pubkey(65) | kh_len(1) | key_handle(96) | cert | att_sig | status(2)
//
// The attestation signature covers:
//   0x00 || app_param || challenge_param || key_handle || public_key

static size_t handle_register(const uint8_t *data, size_t data_len,
                              uint8_t *response) {
    if (data_len != 64) {
        return write_status(response, SW_WRONG_DATA);
    }

    const uint8_t *challenge_param = data;
    const uint8_t *app_param = data + 32;

    // Generate a fresh keypair for this credential
    uint8_t pubkey[PUBLIC_KEY_SIZE];
    uint8_t privkey[PRIVATE_KEY_SIZE];
    if (!crypto_generate_keypair(pubkey, privkey)) {
        return write_status(response, SW_WRONG_DATA);
    }

    // Wrap the private key into a key handle
    uint8_t key_handle[KEY_HANDLE_SIZE];
    if (!crypto_wrap_key(master_secret, privkey, key_handle)) {
        return write_status(response, SW_WRONG_DATA);
    }

    // Clear private key from stack as soon as it's wrapped
    memset(privkey, 0, sizeof(privkey));

    // Build the attestation signature base:
    // 0x00 || app_param(32) || challenge_param(32) || key_handle(96) || pubkey(65)
    uint8_t sig_base[1 + 32 + 32 + KEY_HANDLE_SIZE + PUBLIC_KEY_SIZE];
    size_t sb_pos = 0;
    sig_base[sb_pos++] = 0x00;
    memcpy(sig_base + sb_pos, app_param, 32);       sb_pos += 32;
    memcpy(sig_base + sb_pos, challenge_param, 32);  sb_pos += 32;
    memcpy(sig_base + sb_pos, key_handle, KEY_HANDLE_SIZE);
    sb_pos += KEY_HANDLE_SIZE;
    memcpy(sig_base + sb_pos, pubkey, PUBLIC_KEY_SIZE);
    sb_pos += PUBLIC_KEY_SIZE;

    // Sign with the attestation key
    uint8_t att_sig[SIGNATURE_MAX_SIZE];
    size_t att_sig_len = 0;
    if (!crypto_sign(attestation_privkey, sig_base, sb_pos,
                     att_sig, &att_sig_len)) {
        return write_status(response, SW_WRONG_DATA);
    }

    // Assemble the response
    size_t pos = 0;
    response[pos++] = 0x05;                                    // Reserved byte
    memcpy(response + pos, pubkey, PUBLIC_KEY_SIZE);            // Public key
    pos += PUBLIC_KEY_SIZE;
    response[pos++] = KEY_HANDLE_SIZE;                          // Key handle length
    memcpy(response + pos, key_handle, KEY_HANDLE_SIZE);        // Key handle
    pos += KEY_HANDLE_SIZE;
    memcpy(response + pos, attestation_cert, attestation_cert_len);  // X.509 cert
    pos += attestation_cert_len;
    memcpy(response + pos, att_sig, att_sig_len);               // Attestation signature
    pos += att_sig_len;
    pos += write_status(response + pos, SW_NO_ERROR);           // Status

    return pos;
}

// ---------------------------------------------------------------------------
// U2F_AUTHENTICATE — prove we hold the private key for a credential
// ---------------------------------------------------------------------------
//
// Input:
//   challenge_param(32) + app_param(32) + kh_len(1) + key_handle(kh_len)
//
// Modes:
//   AUTH_CHECK (0x07):   "Do you recognize this key handle?"
//   AUTH_ENFORCE (0x03): "Sign this challenge."
//
// Output (AUTH_ENFORCE):
//   user_presence(1) + counter(4) + signature + status(2)
//
// Signature covers:
//   app_param(32) || user_presence(1) || counter(4) || challenge_param(32)

static size_t handle_authenticate(uint8_t control, const uint8_t *data,
                                  size_t data_len, uint8_t *response) {
    if (data_len < 65) {
        return write_status(response, SW_WRONG_DATA);
    }

    const uint8_t *challenge_param = data;
    const uint8_t *app_param = data + 32;
    uint8_t kh_len = data[64];
    const uint8_t *key_handle = data + 65;

    if (data_len < 65 + kh_len) {
        return write_status(response, SW_WRONG_DATA);
    }

    if (kh_len != KEY_HANDLE_SIZE) {
        return write_status(response, SW_WRONG_DATA);
    }

    // Try to unwrap the key handle
    uint8_t privkey[PRIVATE_KEY_SIZE];
    if (!crypto_unwrap_key(master_secret, key_handle, privkey)) {
        // Key handle doesn't belong to us (wrong master secret or tampered)
        return write_status(response, SW_WRONG_DATA);
    }

    // Check-only mode: "yes I know this handle" → return CONDITIONS_NOT_SATISFIED.
    // The spec uses this status to mean "recognized" in check-only mode.
    if (control == AUTH_CHECK) {
        memset(privkey, 0, sizeof(privkey));
        return write_status(response, SW_CONDITIONS_NOT_SATISFIED);
    }

    if (control != AUTH_ENFORCE) {
        memset(privkey, 0, sizeof(privkey));
        return write_status(response, SW_WRONG_DATA);
    }

    // --- Normal authentication ---

    // User presence: auto-approve for now. A real device would wait
    // for a button press here. TODO: add button support (button.c)
    uint8_t user_presence = 0x01;

    // Increment counter
    sign_counter++;
    uint8_t counter_bytes[4];
    write_be32(counter_bytes, sign_counter);

    // Build the data to sign:
    // app_param(32) || user_presence(1) || counter(4) || challenge_param(32) = 69 bytes
    uint8_t sig_base[69];
    memcpy(sig_base, app_param, 32);
    sig_base[32] = user_presence;
    memcpy(sig_base + 33, counter_bytes, 4);
    memcpy(sig_base + 37, challenge_param, 32);

    // Sign with the per-site private key
    uint8_t sig[SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;
    bool ok = crypto_sign(privkey, sig_base, sizeof(sig_base), sig, &sig_len);
    memset(privkey, 0, sizeof(privkey));  // Clear private key immediately

    if (!ok) {
        return write_status(response, SW_WRONG_DATA);
    }

    // Assemble response
    size_t pos = 0;
    response[pos++] = user_presence;
    memcpy(response + pos, counter_bytes, 4);   pos += 4;
    memcpy(response + pos, sig, sig_len);        pos += sig_len;
    pos += write_status(response + pos, SW_NO_ERROR);

    return pos;
}

// ---------------------------------------------------------------------------
// Message dispatch — parse APDU and route to handler
// ---------------------------------------------------------------------------

size_t u2f_handle_message(const uint8_t *data, size_t data_len,
                          uint8_t *response_buf) {
    if (data_len < 7) {
        return write_status(response_buf, SW_INS_NOT_SUPPORTED);
    }

    // Parse the APDU header (ISO 7816-4 format)
    // Byte 0: CLA (always 0 for U2F)
    // Byte 1: INS (command)
    // Byte 2: P1 (parameter 1)
    // Byte 3: P2 (parameter 2)
    // Bytes 4-6: data length (3 bytes, big-endian — extended APDU)
    uint8_t ins = data[1];
    uint8_t p1 = data[2];
    uint32_t req_len = ((uint32_t)data[4] << 16) | ((uint32_t)data[5] << 8) | data[6];
    const uint8_t *req_data = data + 7;
    size_t req_data_avail = (data_len > 7) ? (data_len - 7) : 0;

    // Clamp to available data
    if (req_len > req_data_avail) {
        req_len = req_data_avail;
    }

    switch (ins) {
        case U2F_REGISTER:
            return handle_register(req_data, req_len, response_buf);
        case U2F_AUTHENTICATE:
            return handle_authenticate(p1, req_data, req_len, response_buf);
        case U2F_VERSION:
            return handle_version(response_buf);
        default:
            return write_status(response_buf, SW_INS_NOT_SUPPORTED);
    }
}
