"""
Test client for the FIDO U2F key over native USB HID.

Unlike the Phase 1 test (test_fido2_client.py) which talks over UDP via
the serial bridge, this talks directly to the RP2040 as a USB HID device.
No bridge needed — this is how a real FIDO key works.

Uses the python-fido2 library's built-in HID transport, which handles:
  - USB HID enumeration (finding devices with FIDO usage page 0xF1D0)
  - HID report sending/receiving (64-byte interrupt IN/OUT transfers)
  - CTAPHID framing (channel allocation, packet fragmentation)

This is the same code path that browsers use to talk to YubiKeys, etc.

NOTE: On macOS, the OS may claim exclusive access to FIDO HID devices
for the system WebAuthn framework. If list_devices() returns nothing,
test with a browser instead (e.g. webauthn.io).

Usage:
    source .venv/bin/activate
    python test_hid.py
"""

import os
import sys
import hashlib

from fido2.hid import CtapHidDevice
from fido2.ctap1 import Ctap1


def find_device():
    """Find our FIDO U2F HID device."""
    print("Searching for FIDO HID devices...")
    devices = list(CtapHidDevice.list_devices())

    if not devices:
        print("\nNo FIDO HID devices found!")
        print("Possible causes:")
        print("  - Device not plugged in or not flashed with HID firmware")
        print("  - macOS is claiming exclusive access (try a browser test instead)")
        print("  - Missing permissions (Linux: check udev rules)")
        sys.exit(1)

    # If multiple devices, try to find ours by VID/PID
    for dev in devices:
        desc = dev.descriptor
        print(f"  Found: VID={desc.vid:#06x} PID={desc.pid:#06x} "
              f"{desc.product_name or '(unnamed)'}")

    # Use the first device (or find ours specifically)
    device = devices[0]
    if len(devices) > 1:
        # Try to find our specific device (VID 0x1209, PID 0xF1D0)
        for dev in devices:
            if dev.descriptor.vid == 0x1209 and dev.descriptor.pid == 0xF1D0:
                device = dev
                break
        print(f"\n  Using: {device.descriptor.product_name or 'first device'}")

    return device


def main():
    print("=" * 60)
    print("FIDO U2F Test — native USB HID")
    print("=" * 60)

    device = find_device()
    ctap1 = Ctap1(device)

    # ------------------------------------------------------------------
    # Step 1: Version
    # ------------------------------------------------------------------
    print("\n[1] Checking U2F version...")
    version = ctap1.get_version()
    print(f"    Version: {version}")
    assert version == "U2F_V2"

    # ------------------------------------------------------------------
    # Step 2: Register
    # ------------------------------------------------------------------
    print("\n[2] Registering credential for 'example.com'...")
    print("    >>> Press BOOTSEL button when LED blinks <<<")

    client_param = os.urandom(32)
    app_param = hashlib.sha256(b"https://example.com").digest()

    reg_data = ctap1.register(client_param, app_param)

    print(f"    Public key:  {reg_data.public_key[:8].hex()}... ({len(reg_data.public_key)} bytes)")
    print(f"    Key handle:  {reg_data.key_handle[:8].hex()}... ({len(reg_data.key_handle)} bytes)")
    print(f"    Certificate: {len(reg_data.certificate)} bytes")

    print("\n    Verifying attestation signature...")
    reg_data.verify(app_param, client_param)
    print("    Attestation: VALID")

    # ------------------------------------------------------------------
    # Step 3: Authenticate
    # ------------------------------------------------------------------
    print("\n[3] Authenticating...")
    print("    >>> Press BOOTSEL button when LED blinks <<<")

    auth_client_param = os.urandom(32)
    sig_data = ctap1.authenticate(auth_client_param, app_param, reg_data.key_handle)

    print(f"    User presence: 0x{sig_data.user_presence:02X}")
    print(f"    Counter:       {sig_data.counter}")

    print("\n    Verifying authentication signature...")
    sig_data.verify(app_param, auth_client_param, reg_data.public_key)
    print("    Authentication: VALID")

    # ------------------------------------------------------------------
    # Step 4: Second auth — counter increment
    # ------------------------------------------------------------------
    print("\n[4] Second authentication — checking counter...")
    print("    >>> Press BOOTSEL button when LED blinks <<<")

    auth_client_param_2 = os.urandom(32)
    sig_data_2 = ctap1.authenticate(auth_client_param_2, app_param, reg_data.key_handle)

    print(f"    Counter: {sig_data_2.counter} (was {sig_data.counter})")
    assert sig_data_2.counter == sig_data.counter + 1, "Counter didn't increment!"
    print("    Counter correctly incremented!")

    sig_data_2.verify(app_param, auth_client_param_2, reg_data.public_key)
    print("    Authentication: VALID")

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    device.close()

    print("\n" + "=" * 60)
    print("All tests passed! Native USB HID authenticator working.")
    print("=" * 60)


if __name__ == "__main__":
    main()
