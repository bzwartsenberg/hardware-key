"""
FIDO U2F Authenticator — UDP virtual device.

This is the "firmware" of our virtual security key. It listens on UDP port
7112 and speaks the CTAPHID protocol, just like a real hardware key would
over USB HID.

Two layers live here:
1. CTAPHID — transport framing. Handles 64-byte packets, channel management,
   message reassembly. Think of it as TCP for USB HID.
2. U2F — application logic. Register and Authenticate commands that use
   the crypto layer to generate credentials and sign challenges.
"""

import socket
import struct
import hashlib

import crypto

# ---------------------------------------------------------------------------
# CTAPHID constants
# ---------------------------------------------------------------------------
# These are defined by the FIDO HID protocol spec. Every FIDO device,
# from a $5 key to a YubiKey, uses these exact same values.

CTAPHID_PACKET_SIZE = 64  # Always 64 bytes, padded with zeros if needed

# Command bytes — the high bit (0x80) is set for initialization packets,
# clear for continuation packets. This is how the receiver knows if a
# packet starts a new message or continues one.
CTAPHID_INIT = 0x80 | 0x06     # Channel allocation handshake
CTAPHID_MSG = 0x80 | 0x03      # Carry a U2F message
CTAPHID_ERROR = 0x80 | 0x3F    # Error response
CTAPHID_KEEPALIVE = 0x80 | 0x3B  # "I'm still working" (e.g., waiting for button)

# The broadcast channel — clients send INIT here before they have a channel
BROADCAST_CID = 0xFFFFFFFF

# Error codes
ERR_INVALID_CMD = 0x01
ERR_INVALID_LEN = 0x03
ERR_INVALID_CHANNEL = 0x0B
ERR_OTHER = 0x7F

# ---------------------------------------------------------------------------
# U2F constants
# ---------------------------------------------------------------------------
# U2F commands travel inside CTAPHID MSG packets. The U2F message format
# is based on ISO 7816 APDUs (the same framing smart cards use — FIDO
# inherited this from the smart card world).

# Command bytes (INS field in the APDU)
U2F_REGISTER = 0x01        # "Make me a new credential"
U2F_AUTHENTICATE = 0x02    # "Sign this challenge"
U2F_VERSION = 0x03         # "What version are you?"

# Authentication control bytes — the P1 field tells us what kind of
# authenticate request this is
AUTH_ENFORCE = 0x03   # Normal authentication — require user presence
AUTH_CHECK = 0x07     # Just check if this key handle belongs to us

# U2F status codes — appended to every response as 2 bytes
SW_NO_ERROR = 0x9000              # Success
SW_CONDITIONS_NOT_SATISFIED = 0x6985  # User didn't press button (or check-only)
SW_WRONG_DATA = 0x6A80           # Bad key handle (doesn't belong to this device)
SW_INS_NOT_SUPPORTED = 0x6D00    # Unknown command


# ---------------------------------------------------------------------------
# CTAPHID layer
# ---------------------------------------------------------------------------

class CTAPHIDLayer:
    """
    Handles CTAPHID packet framing and channel management.

    CTAPHID multiplexes multiple clients over one device. Each client
    gets a unique 4-byte channel ID. Messages longer than one packet
    are split into an initialization packet + continuation packets.

    Packet format (initialization):
      Bytes 0-3:  Channel ID (4 bytes, big-endian)
      Byte 4:     Command (high bit set)
      Bytes 5-6:  Total payload length (big-endian uint16)
      Bytes 7-63: Payload data (first 57 bytes)

    Packet format (continuation):
      Bytes 0-3:  Channel ID
      Byte 4:     Sequence number (0, 1, 2... — high bit clear)
      Bytes 5-63: Payload data (next 59 bytes)
    """

    def __init__(self):
        self._next_cid = 1  # Next channel ID to assign

    def parse_packet(self, data: bytes) -> dict:
        """
        Parse a raw 64-byte CTAPHID packet into its components.

        Returns a dict with channel_id, command, and payload.
        For now we only handle single-packet messages (payload ≤ 57 bytes).
        U2F messages can be longer, but for Phase 1 we'll handle the
        common case and add continuation packet support if needed.
        """
        if len(data) < 7:
            return None

        # Unpack the header: 4 bytes channel, 1 byte command, 2 bytes length
        cid, cmd, length = struct.unpack(">IBH", data[:7])

        # The payload starts at byte 7. We take 'length' bytes (which may
        # be less than the remaining 57 bytes — the rest is zero-padding).
        payload = data[7:7 + length]

        return {"cid": cid, "cmd": cmd, "length": length, "payload": payload}

    def build_response(self, cid: int, cmd: int, payload: bytes) -> list[bytes]:
        """
        Build one or more 64-byte CTAPHID response packets.

        If the payload fits in one packet (≤ 57 bytes), we send one
        initialization packet. If it's longer, we send an init packet
        followed by continuation packets.

        Returns a list of 64-byte packets.
        """
        packets = []

        # First packet: init packet with up to 57 bytes of payload
        first_chunk = payload[:57]
        header = struct.pack(">IBH", cid, cmd, len(payload))
        packet = header + first_chunk
        packet = packet.ljust(CTAPHID_PACKET_SIZE, b'\x00')
        packets.append(packet)

        # Remaining payload goes into continuation packets
        offset = 57
        seq = 0
        while offset < len(payload):
            chunk = payload[offset:offset + 59]  # 59 bytes per continuation
            cont_header = struct.pack(">IB", cid, seq)
            packet = cont_header + chunk
            packet = packet.ljust(CTAPHID_PACKET_SIZE, b'\x00')
            packets.append(packet)
            offset += 59
            seq += 1

        return packets

    def handle_init(self, cid: int, payload: bytes) -> bytes:
        """
        Handle CTAPHID_INIT — the channel allocation handshake.

        When a client first connects, it sends INIT on the broadcast
        channel (0xFFFFFFFF) with 8 bytes of random nonce. We respond
        with that nonce + a fresh channel ID + capability info.

        This is the very first exchange that happens — before any U2F
        commands can be sent.

        Response format (17 bytes):
          Bytes 0-7:   Client's nonce (echoed back)
          Bytes 8-11:  New channel ID (4 bytes)
          Byte 12:     Protocol version (2 for CTAPHID)
          Byte 13:     Major device version
          Byte 14:     Minor device version
          Byte 15:     Build device version
          Byte 16:     Capabilities flags
        """
        nonce = payload[:8]

        # Assign a new channel ID
        new_cid = self._next_cid
        self._next_cid += 1

        response = nonce + struct.pack(">I", new_cid)
        # Version info: protocol 2, device version 0.0.1, no special capabilities
        response += struct.pack("BBBB", 2, 0, 0, 1)
        # Capabilities: 0x00 = no CBOR (CTAP2), no NMSG
        # Real CTAP2 devices set bit flags here; we're U2F only
        response += struct.pack("B", 0x00)

        return response

    def build_error(self, cid: int, error_code: int) -> bytes:
        """Build a CTAPHID error response."""
        return self.build_response(cid, CTAPHID_ERROR, bytes([error_code]))[0]


# ---------------------------------------------------------------------------
# U2F layer
# ---------------------------------------------------------------------------

class U2FAuthenticator:
    """
    Implements U2F Register and Authenticate commands.

    This is the heart of the authenticator — it generates credentials,
    wraps/unwraps keys, signs challenges, and manages the sign counter.
    """

    def __init__(self):
        # The master secret — root of all key wrapping
        self.master_secret = crypto.generate_master_secret()

        # Attestation cert + key — generated once at startup
        # On a real device these would be burned in during manufacturing
        self.attestation_cert_der, self.attestation_key = (
            crypto.generate_attestation_cert()
        )

        # Sign counter — increments on every authentication
        # On a real device this would be in flash with wear leveling
        self.counter = 0

    def handle_u2f_message(self, data: bytes) -> bytes:
        """
        Parse and dispatch a U2F APDU message.

        U2F messages use ISO 7816-4 APDU framing:
          Byte 0:     CLA (class byte, always 0x00 for U2F)
          Byte 1:     INS (instruction — REGISTER, AUTHENTICATE, or VERSION)
          Byte 2:     P1 (parameter 1 — used for auth mode)
          Byte 3:     P2 (parameter 2 — usually 0)
          Bytes 4-6:  Length of request data (3 bytes, big-endian)
          Bytes 7+:   Request data

        The response is: [response data] + [2-byte status code]
        """
        if len(data) < 7:
            return self._status(SW_INS_NOT_SUPPORTED)

        # Parse the APDU header
        cla = data[0]     # Class byte — always 0 for U2F
        ins = data[1]     # Instruction — which command
        p1 = data[2]      # Parameter 1
        p2 = data[3]      # Parameter 2

        # Request data length — 3 bytes big-endian (extended length APDU)
        req_len = (data[4] << 16) | (data[5] << 8) | data[6]
        req_data = data[7:7 + req_len]

        if ins == U2F_REGISTER:
            return self._handle_register(req_data)
        elif ins == U2F_AUTHENTICATE:
            return self._handle_authenticate(p1, req_data)
        elif ins == U2F_VERSION:
            return self._handle_version()
        else:
            return self._status(SW_INS_NOT_SUPPORTED)

    def _handle_version(self) -> bytes:
        """
        U2F_VERSION — return the string "U2F_V2".

        This is how a client confirms we speak U2F. Simple call-and-response.
        """
        return b"U2F_V2" + self._status(SW_NO_ERROR)

    def _handle_register(self, data: bytes) -> bytes:
        """
        U2F_REGISTER — create a new credential for a website.

        Input (64 bytes):
          Bytes 0-31:   Challenge parameter (SHA-256 of client data)
          Bytes 32-63:  Application parameter (SHA-256 of origin/RP ID)

        The "challenge parameter" is the hash of the challenge from the
        relying party. The "application parameter" is the hash of the
        origin (e.g., SHA-256 of "github.com"). These come pre-hashed
        from the client — the authenticator doesn't need to know the
        actual origin string.

        Output:
          Byte 0:       0x05 (reserved byte, always 0x05)
          Bytes 1-65:   Public key (65 bytes, uncompressed P-256 point)
          Byte 66:      Key handle length
          Bytes 67+:    Key handle
          Then:         Attestation certificate (DER-encoded X.509)
          Then:         Attestation signature (DER-encoded ECDSA)

        The attestation signature covers:
          0x00 || app_param || challenge_param || key_handle || public_key

        This binds everything together — the relying party can verify
        that this specific public key and key handle were produced by
        an authenticator that holds the attestation private key.
        """
        if len(data) != 64:
            return self._status(SW_WRONG_DATA)

        challenge_param = data[:32]    # Hash of the challenge
        app_param = data[32:64]        # Hash of the origin

        # Generate a fresh keypair for this credential
        private_key_bytes, public_key_bytes = crypto.generate_key_pair()

        # Wrap the private key into a key handle — this is the "store it
        # on the relying party's side" trick we discussed
        key_handle = crypto.wrap_key(self.master_secret, private_key_bytes)

        # Build the data that gets signed by the attestation key.
        # The 0x00 prefix is just a reserved byte required by the spec.
        sig_base = (
            b'\x00'
            + app_param
            + challenge_param
            + key_handle
            + public_key_bytes
        )

        # Sign with the attestation key (NOT the per-site key).
        # This signature says: "I, this specific authenticator, created
        # this credential." The relying party can check it against the
        # attestation certificate.
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        attestation_sig = self.attestation_key.sign(
            sig_base, _ec.ECDSA(_hashes.SHA256())
        )

        # Assemble the response
        response = bytearray()
        response.append(0x05)                        # Reserved byte
        response.extend(public_key_bytes)             # 65 bytes
        response.append(len(key_handle))              # Key handle length
        response.extend(key_handle)                   # The encrypted private key
        response.extend(self.attestation_cert_der)    # X.509 cert
        response.extend(attestation_sig)              # Attestation signature

        return bytes(response) + self._status(SW_NO_ERROR)

    def _handle_authenticate(self, control: int, data: bytes) -> bytes:
        """
        U2F_AUTHENTICATE — prove we hold the private key for a credential.

        Input:
          Bytes 0-31:   Challenge parameter (SHA-256 of client data)
          Bytes 32-63:  Application parameter (SHA-256 of origin)
          Byte 64:      Key handle length
          Bytes 65+:    Key handle

        There are two modes (controlled by the 'control' / P1 byte):
          AUTH_CHECK (0x07):   "Do you recognize this key handle?"
                               Just check, don't sign. Used by the client
                               to test which authenticator a credential
                               belongs to.
          AUTH_ENFORCE (0x03): "Sign this challenge." Normal authentication
                               with user presence required.

        Output (for AUTH_ENFORCE):
          Byte 0:       User presence byte (0x01 = user was present)
          Bytes 1-4:    Counter (big-endian uint32)
          Bytes 5+:     Signature (DER-encoded ECDSA)

        The signature covers:
          app_param || user_presence || counter || challenge_param

        This is the data the relying party will verify. It binds the
        origin, user presence, counter (clone detection), and challenge
        (freshness) into one signed package.
        """
        if len(data) < 65:
            return self._status(SW_WRONG_DATA)

        challenge_param = data[:32]
        app_param = data[32:64]
        kh_len = data[64]
        key_handle = data[65:65 + kh_len]

        # Try to unwrap the key handle. If this fails, the key handle
        # doesn't belong to us (wrong master secret or tampered).
        private_key_bytes = crypto.unwrap_key(self.master_secret, key_handle)
        if private_key_bytes is None:
            return self._status(SW_WRONG_DATA)

        # Check-only mode: "yes I know this key handle, but don't sign"
        # We return CONDITIONS_NOT_SATISFIED which, confusingly, means
        # "yes this is mine" in check-only mode. The spec is weird here.
        if control == AUTH_CHECK:
            return self._status(SW_CONDITIONS_NOT_SATISFIED)

        if control != AUTH_ENFORCE:
            return self._status(SW_WRONG_DATA)

        # --- Normal authentication ---

        # User presence: on a real device, this would wait for a button
        # press. We just auto-approve. The 0x01 byte means "user present."
        user_presence = b'\x01'

        # Increment and encode the counter
        self.counter += 1
        counter_bytes = struct.pack(">I", self.counter)

        # Build the data to sign:
        # app_param (32) || user_presence (1) || counter (4) || challenge_param (32)
        sig_base = app_param + user_presence + counter_bytes + challenge_param

        # Sign with the per-site private key (unwrapped from the key handle)
        signature = crypto.sign(private_key_bytes, sig_base)

        # Assemble the response
        response = user_presence + counter_bytes + signature

        return response + self._status(SW_NO_ERROR)

    def _status(self, code: int) -> bytes:
        """Encode a 2-byte U2F status code, big-endian."""
        return struct.pack(">H", code)


# ---------------------------------------------------------------------------
# UDP server — ties it all together
# ---------------------------------------------------------------------------

def main():
    """
    Run the authenticator as a UDP server on localhost:7112.

    Port 7112 is the conventional port for FIDO virtual devices —
    python-fido2 and other tools know to look here.

    Each UDP datagram = one 64-byte CTAPHID packet. UDP is a natural
    fit because it's packet-oriented (unlike TCP which is a byte stream),
    so each datagram maps 1:1 to a CTAPHID packet.

    Messages longer than 57 bytes are split across multiple packets:
    an initialization packet (57 bytes of payload) followed by
    continuation packets (59 bytes each). We reassemble them here
    before passing the complete message to the U2F layer.
    """
    ctap = CTAPHIDLayer()
    u2f = U2FAuthenticator()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 7112))

    print("U2F authenticator listening on UDP 127.0.0.1:7112")
    print(f"Master secret: {u2f.master_secret.hex()}")
    print("Waiting for packets...")

    # Reassembly state: when a message spans multiple packets, we
    # buffer here until all continuation packets arrive.
    pending = {}  # cid -> {"cmd": int, "length": int, "payload": bytearray, "addr": addr}

    while True:
        data, addr = sock.recvfrom(CTAPHID_PACKET_SIZE)

        if len(data) < 5:
            continue

        # Check if this is an initialization packet (high bit set on byte 4)
        # or a continuation packet (high bit clear).
        cid = struct.unpack(">I", data[:4])[0]
        is_init = (data[4] & 0x80) != 0

        if is_init:
            # Initialization packet: start of a new message
            cmd = data[4]
            length = struct.unpack(">H", data[5:7])[0]
            payload = data[7:7 + min(length, 57)]

            if len(payload) >= length:
                # Complete message in one packet — process immediately
                full_payload = payload[:length]
            else:
                # Need continuation packets — buffer and wait
                pending[cid] = {
                    "cmd": cmd,
                    "length": length,
                    "payload": bytearray(payload),
                    "addr": addr,
                }
                continue
        else:
            # Continuation packet: append to pending message
            if cid not in pending:
                continue  # No pending message for this channel, ignore
            seq = data[4]  # Sequence number (we don't validate order here)
            pending[cid]["payload"].extend(data[5:])
            if len(pending[cid]["payload"]) < pending[cid]["length"]:
                continue  # Still waiting for more packets
            # Message complete — extract and clean up
            cmd = pending[cid]["cmd"]
            length = pending[cid]["length"]
            full_payload = bytes(pending[cid]["payload"][:length])
            addr = pending[cid]["addr"]
            del pending[cid]

        # --- Full message received, dispatch ---

        if cmd == CTAPHID_INIT:
            # Channel allocation — works on broadcast or any channel
            response_payload = ctap.handle_init(cid, full_payload)
            response_cid = cid if cid != BROADCAST_CID else BROADCAST_CID
            for packet in ctap.build_response(response_cid, CTAPHID_INIT, response_payload):
                sock.sendto(packet, addr)

        elif cmd == CTAPHID_MSG:
            # U2F message inside a MSG command
            response_data = u2f.handle_u2f_message(full_payload)
            for packet in ctap.build_response(cid, CTAPHID_MSG, response_data):
                sock.sendto(packet, addr)

        else:
            # Unknown command
            sock.sendto(ctap.build_error(cid, ERR_INVALID_CMD), addr)


if __name__ == "__main__":
    main()
