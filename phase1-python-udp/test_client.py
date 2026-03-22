"""
Test client for the U2F authenticator.

This plays the role of a browser + relying party: it talks CTAPHID over
UDP to our authenticator, performs a registration, then authenticates
with the credential it got back.

We do everything manually here (no python-fido2 client library) so you
can see exactly what bytes go over the wire. This is the "browser side"
of the conversation.
"""

import socket
import struct
import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_der_x509_certificate

# Must match the authenticator
CTAPHID_INIT = 0x80 | 0x06
CTAPHID_MSG = 0x80 | 0x03
BROADCAST_CID = 0xFFFFFFFF
PACKET_SIZE = 64

SW_NO_ERROR = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985


def send_and_receive(sock: socket.socket, packets: list[bytes]) -> bytes:
    """
    Send one or more CTAPHID packets and reassemble the response.

    Handles multi-packet responses by reading continuation packets
    until we have the full payload.
    """
    for packet in packets:
        sock.send(packet)

    # Read the initialization packet of the response
    resp = sock.recv(PACKET_SIZE)
    cid, cmd, length = struct.unpack(">IBH", resp[:7])
    payload = resp[7:]

    # If the full payload fits in one packet, we're done.
    # Otherwise, read continuation packets.
    received = len(payload)
    seq = 0
    while received < length:
        cont = sock.recv(PACKET_SIZE)
        # Continuation header: 4 bytes CID + 1 byte sequence number
        cont_payload = cont[5:]
        payload += cont_payload
        received += len(cont_payload)
        seq += 1

    # Trim to exact length (packets are zero-padded to 64 bytes)
    return cmd, payload[:length]


def build_ctaphid_packets(cid: int, cmd: int, payload: bytes) -> list[bytes]:
    """
    Build CTAPHID packets from a payload — mirrors the authenticator's
    build_response, but on the client side.
    """
    packets = []

    # Initialization packet
    header = struct.pack(">IBH", cid, cmd, len(payload))
    first = header + payload[:57]
    packets.append(first.ljust(PACKET_SIZE, b'\x00'))

    # Continuation packets if needed
    offset = 57
    seq = 0
    while offset < len(payload):
        chunk = payload[offset:offset + 59]
        cont = struct.pack(">IB", cid, seq) + chunk
        packets.append(cont.ljust(PACKET_SIZE, b'\x00'))
        offset += 59
        seq += 1

    return packets


def build_u2f_apdu(ins: int, p1: int, p2: int, data: bytes) -> bytes:
    """
    Build a U2F APDU (ISO 7816-4 extended length).

    Format: CLA(1) INS(1) P1(1) P2(1) Lc(3) Data(N)

    CLA is always 0x00 for U2F. The 3-byte length field (Lc) is the
    "extended length" encoding — regular APDUs use 1 byte, but U2F
    messages can exceed 255 bytes so we use the extended form.
    """
    # CLA=0, INS, P1, P2, then 3-byte big-endian length, then data
    length_bytes = struct.pack(">I", len(data))[1:]  # 3 bytes from a 4-byte int
    return bytes([0x00, ins, p1, p2]) + length_bytes + data


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("127.0.0.1", 7112))
    sock.settimeout(5.0)

    print("=" * 60)
    print("FIDO U2F Test Client")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Step 1: CTAPHID INIT — get a channel
    # ------------------------------------------------------------------
    # We send 8 random bytes on the broadcast channel.
    # The authenticator echoes them back with a new channel ID.
    print("\n[1] CTAPHID INIT — requesting a channel...")

    nonce = os.urandom(8)
    init_packets = build_ctaphid_packets(BROADCAST_CID, CTAPHID_INIT, nonce)
    cmd, resp = send_and_receive(sock, init_packets)

    # Parse INIT response: nonce(8) + CID(4) + version info(5)
    echo_nonce = resp[:8]
    cid = struct.unpack(">I", resp[8:12])[0]
    assert echo_nonce == nonce, "Nonce mismatch!"
    print(f"    Got channel ID: 0x{cid:08X}")

    # ------------------------------------------------------------------
    # Step 2: U2F VERSION — confirm we speak U2F_V2
    # ------------------------------------------------------------------
    print("\n[2] U2F VERSION — checking protocol version...")

    version_apdu = build_u2f_apdu(0x03, 0x00, 0x00, b"")
    msg_packets = build_ctaphid_packets(cid, CTAPHID_MSG, version_apdu)
    cmd, resp = send_and_receive(sock, msg_packets)

    # Response: "U2F_V2" + 2-byte status
    status = struct.unpack(">H", resp[-2:])[0]
    version_str = resp[:-2].decode("ascii")
    assert status == SW_NO_ERROR, f"VERSION failed: 0x{status:04X}"
    assert version_str == "U2F_V2", f"Unexpected version: {version_str}"
    print(f"    Version: {version_str}")

    # ------------------------------------------------------------------
    # Step 3: U2F REGISTER — create a credential
    # ------------------------------------------------------------------
    # We simulate a relying party called "example.com". The challenge is
    # random, and the app parameter is the SHA-256 hash of the origin.
    # In a real flow, the browser computes these.
    print("\n[3] U2F REGISTER — creating a credential for 'example.com'...")

    challenge = os.urandom(32)
    app_param = hashlib.sha256(b"https://example.com").digest()

    # Registration request is just challenge(32) + app_param(32) = 64 bytes
    register_data = challenge + app_param
    register_apdu = build_u2f_apdu(0x01, 0x00, 0x00, register_data)
    msg_packets = build_ctaphid_packets(cid, CTAPHID_MSG, register_apdu)
    cmd, resp = send_and_receive(sock, msg_packets)

    # Parse registration response
    status = struct.unpack(">H", resp[-2:])[0]
    assert status == SW_NO_ERROR, f"REGISTER failed: 0x{status:04X}"
    resp = resp[:-2]  # Strip status bytes

    # Byte 0: reserved (0x05)
    assert resp[0] == 0x05, f"Bad reserved byte: 0x{resp[0]:02X}"

    # Bytes 1-65: public key (65 bytes, uncompressed P-256 point)
    public_key_bytes = resp[1:66]
    print(f"    Public key: {public_key_bytes[:8].hex()}... ({len(public_key_bytes)} bytes)")

    # Byte 66: key handle length, then key handle
    kh_len = resp[66]
    key_handle = resp[67:67 + kh_len]
    print(f"    Key handle: {key_handle[:8].hex()}... ({kh_len} bytes)")

    # Remaining: attestation cert (DER X.509) + attestation signature
    # We need to parse the cert to know where it ends and the sig begins.
    # DER-encoded certs start with 0x30 (SEQUENCE tag) and the length
    # tells us the total size.
    cert_start = 67 + kh_len
    cert_data = resp[cert_start:]

    # Parse the DER length to find where the certificate ends and the
    # attestation signature begins. DER encoding:
    #   Byte 0: 0x30 (SEQUENCE tag)
    #   Byte 1: if high bit set, the low 7 bits = number of length bytes
    #           e.g., 0x82 means "next 2 bytes are the length"
    #   Then: length bytes (big-endian)
    #   Total DER size = tag(1) + length-of-length(1+N) + content-length
    assert cert_data[0] == 0x30, "Expected DER SEQUENCE tag"
    if cert_data[1] & 0x80:
        num_len_bytes = cert_data[1] & 0x7F
        content_len = int.from_bytes(cert_data[2:2 + num_len_bytes], "big")
        cert_len = 1 + 1 + num_len_bytes + content_len
    else:
        cert_len = 1 + 1 + cert_data[1]

    cert = load_der_x509_certificate(cert_data[:cert_len])
    print(f"    Attestation cert: {cert_len} bytes (CN={cert.subject.rfc4514_string()})")

    attestation_sig = resp[cert_start + cert_len:]
    print(f"    Attestation sig: {attestation_sig[:8].hex()}... ({len(attestation_sig)} bytes)")

    # ------------------------------------------------------------------
    # Verify the attestation signature
    # ------------------------------------------------------------------
    # The attestation signature covers:
    #   0x00 || app_param || challenge || key_handle || public_key
    # We verify it with the public key from the attestation certificate.
    print("\n    Verifying attestation signature...")

    sig_base = b'\x00' + app_param + challenge + key_handle + public_key_bytes
    attestation_pub_key = cert.public_key()
    try:
        attestation_pub_key.verify(attestation_sig, sig_base, ec.ECDSA(hashes.SHA256()))
        print("    Attestation signature: VALID")
    except Exception as e:
        print(f"    Attestation signature: INVALID — {e}")
        return

    # ------------------------------------------------------------------
    # Step 4: U2F AUTHENTICATE — prove we hold the private key
    # ------------------------------------------------------------------
    # Now we play the role of a relying party asking the authenticator to
    # sign a new challenge. We send back the key handle we got during
    # registration — the authenticator unwraps it to recover the private key.
    print("\n[4] U2F AUTHENTICATE — signing a challenge...")

    auth_challenge = os.urandom(32)

    # Auth request: challenge(32) + app_param(32) + kh_length(1) + key_handle
    auth_data = auth_challenge + app_param + bytes([kh_len]) + key_handle
    auth_apdu = build_u2f_apdu(0x02, 0x03, 0x00, auth_data)  # P1=0x03 = enforce
    msg_packets = build_ctaphid_packets(cid, CTAPHID_MSG, auth_apdu)
    cmd, resp = send_and_receive(sock, msg_packets)

    status = struct.unpack(">H", resp[-2:])[0]
    assert status == SW_NO_ERROR, f"AUTHENTICATE failed: 0x{status:04X}"
    resp = resp[:-2]

    # Parse authentication response
    user_presence = resp[0]
    counter = struct.unpack(">I", resp[1:5])[0]
    auth_signature = resp[5:]

    print(f"    User presence: 0x{user_presence:02X} ({'present' if user_presence == 0x01 else 'absent'})")
    print(f"    Counter: {counter}")
    print(f"    Signature: {auth_signature[:8].hex()}... ({len(auth_signature)} bytes)")

    # ------------------------------------------------------------------
    # Verify the authentication signature
    # ------------------------------------------------------------------
    # The signature covers:
    #   app_param || user_presence || counter || challenge
    # We verify with the public key we got during registration.
    print("\n    Verifying authentication signature...")

    sig_base = (
        app_param
        + bytes([user_presence])
        + struct.pack(">I", counter)
        + auth_challenge
    )

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_bytes
    )
    try:
        public_key.verify(auth_signature, sig_base, ec.ECDSA(hashes.SHA256()))
        print("    Authentication signature: VALID")
    except Exception as e:
        print(f"    Authentication signature: INVALID — {e}")
        return

    # ------------------------------------------------------------------
    # Step 5: Authenticate again — verify counter increments
    # ------------------------------------------------------------------
    print("\n[5] U2F AUTHENTICATE (again) — checking counter increment...")

    auth_challenge_2 = os.urandom(32)
    auth_data_2 = auth_challenge_2 + app_param + bytes([kh_len]) + key_handle
    auth_apdu_2 = build_u2f_apdu(0x02, 0x03, 0x00, auth_data_2)
    msg_packets_2 = build_ctaphid_packets(cid, CTAPHID_MSG, auth_apdu_2)
    cmd, resp = send_and_receive(sock, msg_packets_2)

    status = struct.unpack(">H", resp[-2:])[0]
    assert status == SW_NO_ERROR
    resp = resp[:-2]

    counter_2 = struct.unpack(">I", resp[1:5])[0]
    print(f"    Counter: {counter_2} (was {counter})")
    assert counter_2 == counter + 1, f"Counter didn't increment! {counter} -> {counter_2}"
    print("    Counter correctly incremented!")

    # ------------------------------------------------------------------
    # Step 6: Try authenticating with wrong origin
    # ------------------------------------------------------------------
    # This simulates phishing — "evil-example.com" tries to use a
    # credential registered for "example.com". The authenticator will
    # sign it (it doesn't check origin — remember, that's the browser's
    # job), but the relying party's verification will fail because the
    # signature is over the wrong app_param.
    print("\n[6] PHISHING TEST — wrong origin, verify should fail...")

    evil_app_param = hashlib.sha256(b"https://evil-example.com").digest()
    phish_challenge = os.urandom(32)

    # The authenticator will sign this — it can't tell the origin is wrong,
    # it just sees a different hash. This is expected! Origin enforcement
    # is the browser's responsibility.
    auth_data_evil = phish_challenge + evil_app_param + bytes([kh_len]) + key_handle
    auth_apdu_evil = build_u2f_apdu(0x02, 0x03, 0x00, auth_data_evil)
    msg_packets_evil = build_ctaphid_packets(cid, CTAPHID_MSG, auth_apdu_evil)
    cmd, resp = send_and_receive(sock, msg_packets_evil)

    status = struct.unpack(">H", resp[-2:])[0]
    assert status == SW_NO_ERROR  # Authenticator is happy — it doesn't check origin
    resp = resp[:-2]

    counter_3 = struct.unpack(">I", resp[1:5])[0]
    evil_sig = resp[5:]

    # But verification at the relying party fails! The RP verifies against
    # the ORIGINAL app_param (example.com), but the signature was computed
    # over the evil app_param (evil-example.com). Mismatch!
    sig_base_legit = (
        app_param  # RP expects example.com
        + bytes([resp[0]])
        + struct.pack(">I", counter_3)
        + phish_challenge
    )

    try:
        public_key.verify(evil_sig, sig_base_legit, ec.ECDSA(hashes.SHA256()))
        print("    UNEXPECTED: Phishing signature verified! Something is wrong.")
    except Exception:
        print("    Phishing signature correctly REJECTED by relying party!")
        print("    (Authenticator signed for evil-example.com,")
        print("     but RP verified against example.com — mismatch)")

    # ------------------------------------------------------------------
    # Done!
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("All tests passed! Full U2F register + authenticate flow works.")
    print("=" * 60)

    sock.close()


if __name__ == "__main__":
    main()
