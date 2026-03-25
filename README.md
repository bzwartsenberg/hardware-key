# DIY FIDO U2F Hardware Security Key

A from-scratch FIDO U2F hardware security key, built as a learning project to understand the FIDO protocol, ECDSA cryptography, and embedded C development. The end goal is a working authenticator integrated into a custom mechanical keyboard.

## How it works

A FIDO U2F security key does two things:

1. **Register** — When you sign up for a site, the key generates a unique ECDSA P-256 keypair. The private key is encrypted (wrapped) with a device master secret and handed back to the site as a "key handle." The public key and a self-signed attestation certificate are also returned.

2. **Authenticate** — When you log in, the site sends back the key handle. The key decrypts it to recover the private key, signs a challenge, and returns the signature. The site verifies it against the stored public key.

The clever part: the key doesn't store any per-site state. Every credential is encoded in its key handle, encrypted so only this device can read it. This means the key supports unlimited credentials with zero on-device storage.

## Project structure

### Phase 1 — Python reference implementation (complete)

A working U2F authenticator running as a UDP server on localhost. Useful for understanding the protocol without hardware.

```bash
source .venv/bin/activate
pip install -r requirements.txt

cd phase1-python-udp
python authenticator.py --verbose    # start authenticator (verbose shows all crypto steps)
python test_fido2_client.py          # test with official python-fido2 library
python test_client.py                # hand-rolled test with phishing detection
```

### Phase 2 — RP2040 C firmware (complete)

The same authenticator ported to C, running on an RP2040 Pro Micro. Presents as a native USB HID device (FIDO usage page 0xF1D0) — browsers and OS WebAuthn APIs talk to it directly, no bridge needed.

**Prerequisites:**
- [Pico SDK](https://github.com/raspberrypi/pico-sdk) installed (set `PICO_SDK_PATH` env var)
- ARM cross-compiler: `brew install arm-none-eabi-gcc`
- cmake and make

**Build:**
```bash
cd phase2-rp2040/build
PICO_SDK_PATH=~/pico-sdk cmake ..
make -j$(sysctl -n hw.ncpu)
```

**Flash:**
Hold BOOTSEL button, plug in the board, then:
```bash
cp build/authenticator.uf2 /Volumes/RPI-RP2/
```
Wait for the LED to blink twice (device ready).

**Test with Python (native HID):**
```bash
source .venv/bin/activate
python test_hid.py
```
Press BOOTSEL when the LED blinks to approve register/authenticate requests.

**Test with a browser:**
```bash
python3 -m http.server 8000
```
Open http://localhost:8000/test_browser.html in Chrome or Safari. Click Register, then press BOOTSEL when the LED blinks. Tested on Chrome and Safari (macOS).

**Test with serial bridge (legacy):**
The serial bridge is still available for testing with Phase 1 UDP clients. Requires building the firmware with `pico_enable_stdio_usb` re-enabled (see git history).

**Run crypto benchmarks:**
```bash
cp build/test_crypto.uf2 /Volumes/RPI-RP2/
screen /dev/cu.usbmodem* 115200    # exit: Ctrl-A then \
```

## Architecture

```
[Browser / WebAuthn API]
       |
       | USB HID (FIDO usage page 0xF1D0, 64-byte interrupt transfers)
       |
[RP2040 firmware]
  ├── main.c             — USB HID event loop (TinyUSB)
  ├── usb_descriptors.c  — USB device identity (descriptors + TinyUSB callbacks)
  ├── ctaphid.c          — CTAPHID transport (framing, channels, reassembly)
  ├── u2f.c              — U2F commands (register, authenticate, attestation cert)
  ├── crypto.c           — ECDSA P-256, AES-256-CBC key wrapping, SHA-256
  ├── storage.c          — flash persistence (master secret + sign counter)
  └── button.c           — user presence via BOOTSEL button
```

## What's next — Phase 4: keyboard integration

Embed the authenticator into a QMK keyboard as a USB composite device (HID keyboard + HID FIDO on one USB connection).

**Plan:**
1. Pick a target RP2040 keyboard/PCB and determine which USB stack QMK uses for it (ChibiOS native or TinyUSB wrapper)
2. Get QMK building and running with basic keyboard functionality
3. Add a FIDO HID interface (usage page 0xF1D0) alongside QMK's existing keyboard interface
4. Port the FIDO C modules (crypto, ctaphid, u2f, storage) into QMK's build — these have zero USB dependencies and should drop in cleanly
5. Rewrite the transport layer (~50 lines) for QMK's USB stack
6. User presence via a dedicated key instead of BOOTSEL

**Fallback:** Two separate MCUs sharing USB via a hub chip (simpler isolation, more hardware).

## Future: CTAP2/FIDO2 upgrade

The device currently speaks U2F (CTAP1) only. Upgrading to CTAP2 (FIDO2) would add PIN support, eliminate Chrome's U2F fallback dance, and enable modern passwordless flows. Planned in three incremental steps:

**Step 1 — CTAP2 basics (no PIN, no resident keys)**
Add CBOR encoding/decoding (vendor nanocbor or tinycbor), implement `authenticatorGetInfo`, `authenticatorMakeCredential`, and `authenticatorGetAssertion`. Same stateless key-wrapping crypto, just a new message format. The device would advertise both `"U2F_V2"` and `"FIDO_2_0"`. This alone fixes Chrome compatibility natively — no more CTAP2→U2F fallback.

**Step 2 — PIN protocol**
CTAP2 PIN/UV uses ECDH key agreement (ephemeral keypair per session) to establish a shared secret, then the PIN is hashed client-side and encrypted before transmission. The device stores a PIN hash + retry counter in flash. All the crypto primitives we already have (ECDSA P-256, SHA-256, AES) are exactly what the PIN protocol needs. With a PIN, stealing the physical key isn't enough — you also need the PIN.

**Step 3 — Resident keys (optional)**
Enables passwordless login by storing credentials on-device (flash) instead of relying on the site to send back the key handle. Requires credential enumeration and flash storage management. Interesting but not essential for a key that lives in a keyboard.

## Security considerations

The master secret is stored **in plain text on the RP2040's external SPI flash chip**. The RP2040 has no internal flash — all data (firmware and secrets) lives on an external QSPI chip that can be physically read. An attacker with physical access could desolder or probe the flash chip, extract the master secret, and use it to unwrap any key handle and forge authentication signatures.

For comparison, commercial FIDO keys (YubiKey, Titan) use secure elements with non-extractable internal storage. This project does not provide that level of hardware security. For a personal keyboard that lives on your desk, this is an acceptable tradeoff — extracting the secret requires targeted hardware attack AND access to the key handles (stored server-side). But if you're considering this for higher-security use cases, be aware of this limitation.

Possible mitigations (not yet implemented):
- Store the master secret in the RP2040's **OTP fuses** (one-time programmable, resistant to flash extraction, but irreversible — no factory reset)
- Encrypt the master secret in flash using a key derived from OTP (reversible factory reset, still resistant to flash extraction)
- Use a **secure element** (e.g. ATECC608) for key storage (strongest, but adds hardware complexity)

## Production-readiness TODOs

Things to address before this becomes a real daily-use authenticator:

- **Verify master secret survives reflash** — The UF2 bootloader appears to only erase sectors covered by the firmware binary, so the storage sector (last 4KB) survives. This needs deliberate verification — if it's reliable, add an explicit factory reset mechanism. If not, reserve a flash region or use RP2040 OTP fuses.
- **Two-sector ping-pong storage** — The flash storage has a brief window (~50ms every ~1014 authentications) where the master secret only lives in RAM during sector rebuild. Using two alternating sectors eliminates this: write to the inactive sector first, then switch. Cost: 4KB extra flash.
- **Full CTAPHID channel multiplexing** — Currently supports one pending message at a time with no channel ID validation. For real USB HID with concurrent clients: track allocated channels, support per-channel reassembly, reject unallocated channels.

## Dependencies

**Python** (Phase 1 + bridge): `fido2`, `cryptography`, `pyserial` — see `requirements.txt`

**C firmware** (Phase 2):
- [Pico SDK](https://github.com/raspberrypi/pico-sdk) — provides pico_stdlib, pico_rand, mbedtls (SHA-256, AES, HMAC)
- [micro-ecc](https://github.com/kmackay/micro-ecc) — vendored, ECDSA P-256 only
