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

## What's next

- Keyboard integration — Embed into a custom mechanical keyboard (USB composite: HID keyboard + HID FIDO)

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
