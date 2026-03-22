"""
Test client using the official python-fido2 library.

This proves our authenticator is compatible with a real FIDO client
implementation — not just our hand-rolled test. The python-fido2 library
handles all CTAPHID framing, U2F APDU construction, response parsing,
and signature verification internally.

We only need to provide one custom piece: a UDP transport that sends
and receives 64-byte packets over localhost:7112 instead of USB HID.
"""

import os
import hashlib
import socket

from fido2.hid.base import CtapHidConnection, HidDescriptor
from fido2.hid import CtapHidDevice
from fido2.ctap1 import Ctap1


# ---------------------------------------------------------------------------
# UDP transport — the only custom piece
# ---------------------------------------------------------------------------
# The python-fido2 library talks to FIDO devices through a CtapHidConnection,
# which is an abstract class with two methods: read_packet() and write_packet().
# Normally this goes over USB HID, but we just swap in UDP sockets.
# The CTAPHID protocol on top (channel allocation, packet framing, etc.)
# is handled entirely by the library — same code path as talking to a
# real YubiKey.

class UdpHidConnection(CtapHidConnection):
    """CTAPHID connection over UDP — drop-in replacement for USB HID."""

    def __init__(self, host: str = "127.0.0.1", port: int = 7112):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect((host, port))
        self.sock.settimeout(5.0)

    def read_packet(self) -> bytes:
        """Read one 64-byte CTAPHID packet from the authenticator."""
        return self.sock.recv(64)

    def write_packet(self, data: bytes) -> None:
        """Send one 64-byte CTAPHID packet to the authenticator."""
        # Pad to 64 bytes if needed (the library may send shorter)
        self.sock.send(data.ljust(64, b'\x00'))

    def close(self) -> None:
        self.sock.close()


def main():
    print("=" * 60)
    print("FIDO U2F Test — using python-fido2 library")
    print("=" * 60)

    # Create a device descriptor (metadata about the device — normally
    # comes from USB enumeration, but we fill it in manually)
    descriptor = HidDescriptor(
        path="udp://127.0.0.1:7112",
        vid=0x1234,
        pid=0x5678,
        report_size_in=64,
        report_size_out=64,
        product_name="DIY FIDO U2F Authenticator",
        serial_number="VIRTUAL-001",
    )

    # Connect over UDP
    connection = UdpHidConnection()

    # Wrap in CtapHidDevice — this handles CTAPHID framing (INIT,
    # channel allocation, packet fragmentation/reassembly). We don't
    # write any of that — the library does it all.
    device = CtapHidDevice(descriptor, connection)

    # Create a Ctap1 (U2F) interface on top of the device.
    # This gives us register() and authenticate() methods that
    # construct the correct APDUs internally.
    ctap1 = Ctap1(device)

    # ------------------------------------------------------------------
    # Step 1: Check version
    # ------------------------------------------------------------------
    print("\n[1] Checking U2F version...")
    version = ctap1.get_version()
    print(f"    Version: {version}")
    assert version == "U2F_V2"

    # ------------------------------------------------------------------
    # Step 2: Register
    # ------------------------------------------------------------------
    # The library's register() takes two 32-byte params:
    #   client_param: SHA-256 of the ClientData JSON (challenge + origin)
    #   app_param:    SHA-256 of the application ID (origin)
    #
    # In a real browser flow, client_param = SHA256(JSON with challenge,
    # origin, type). Here we just use random bytes for the challenge
    # part and hash "https://example.com" for the app param.
    print("\n[2] Registering credential for 'example.com'...")

    client_param = os.urandom(32)  # Simulates SHA-256 of ClientData
    app_param = hashlib.sha256(b"https://example.com").digest()

    # This single call does everything:
    # - Builds the U2F REGISTER APDU
    # - Wraps it in CTAPHID MSG packets
    # - Sends over UDP, reassembles multi-packet response
    # - Parses the response into public_key, key_handle, cert, signature
    reg_data = ctap1.register(client_param, app_param)

    print(f"    Public key:   {reg_data.public_key[:8].hex()}... ({len(reg_data.public_key)} bytes)")
    print(f"    Key handle:   {reg_data.key_handle[:8].hex()}... ({len(reg_data.key_handle)} bytes)")
    print(f"    Certificate:  {len(reg_data.certificate)} bytes")
    print(f"    Signature:    {reg_data.signature[:8].hex()}... ({len(reg_data.signature)} bytes)")

    # Verify attestation — the library checks that the attestation
    # signature is valid against the certificate's public key.
    # This is the same check a relying party would do.
    print("\n    Verifying attestation signature...")
    reg_data.verify(app_param, client_param)
    print("    Attestation: VALID")

    # ------------------------------------------------------------------
    # Step 3: Authenticate
    # ------------------------------------------------------------------
    print("\n[3] Authenticating with credential...")

    auth_client_param = os.urandom(32)

    # authenticate() takes the same params plus the key handle from
    # registration. It builds U2F AUTHENTICATE, sends it, and parses
    # the response (user_presence, counter, signature).
    sig_data = ctap1.authenticate(auth_client_param, app_param, reg_data.key_handle)

    print(f"    User presence: 0x{sig_data.user_presence:02X}")
    print(f"    Counter:       {sig_data.counter}")
    print(f"    Signature:     {sig_data.signature[:8].hex()}... ({len(sig_data.signature)} bytes)")

    # Verify authentication signature using the public key from registration
    print("\n    Verifying authentication signature...")
    sig_data.verify(app_param, auth_client_param, reg_data.public_key)
    print("    Authentication: VALID")

    # ------------------------------------------------------------------
    # Step 4: Authenticate again — counter should increment
    # ------------------------------------------------------------------
    print("\n[4] Second authentication — checking counter...")

    auth_client_param_2 = os.urandom(32)
    sig_data_2 = ctap1.authenticate(auth_client_param_2, app_param, reg_data.key_handle)

    print(f"    Counter: {sig_data_2.counter} (was {sig_data.counter})")
    assert sig_data_2.counter == sig_data.counter + 1, "Counter didn't increment!"
    print("    Counter correctly incremented!")

    # Verify this one too
    sig_data_2.verify(app_param, auth_client_param_2, reg_data.public_key)
    print("    Authentication: VALID")

    # ------------------------------------------------------------------
    # Done!
    # ------------------------------------------------------------------
    device.close()

    print("\n" + "=" * 60)
    print("All tests passed! Authenticator is python-fido2 compatible.")
    print("=" * 60)


if __name__ == "__main__":
    main()
