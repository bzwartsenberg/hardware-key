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

### Phase 2 — RP2040 C firmware (in progress)

The same authenticator ported to C, running on an RP2040 Pro Micro. Communicates over USB serial with a Python bridge that translates to/from UDP, so the Phase 1 test clients work unchanged.

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

**Test end-to-end:**
```bash
# Terminal 1: start the serial bridge
cd phase2-rp2040/bridge
python serial_bridge.py /dev/cu.usbmodem*

# Terminal 2: run test client
cd phase1-python-udp
python test_fido2_client.py
```

**Run crypto benchmarks:**
```bash
cp build/test_crypto.uf2 /Volumes/RPI-RP2/
screen /dev/cu.usbmodem* 115200    # exit: Ctrl-A then \
```

## Architecture

```
[Browser/Client]
       |
       | UDP (port 7112)
       |
[serial_bridge.py]  ← translates UDP <-> serial
       |
       | USB CDC serial (raw binary, 64-byte packets)
       |
[RP2040 firmware]
  ├── main.c       — packet I/O loop
  ├── ctaphid.c    — CTAPHID transport (framing, channels, reassembly)
  ├── u2f.c        — U2F commands (register, authenticate, attestation cert)
  └── crypto.c     — ECDSA P-256, AES-256-CBC key wrapping, SHA-256
```

## What's next

- `storage.c` — Flash persistence for master secret and sign counter
- `button.c` — User presence via GPIO (or BOOTSEL button)
- USB HID — Replace serial bridge with native USB HID device class
- Keyboard integration — Embed into a custom mechanical keyboard

## Dependencies

**Python** (Phase 1 + bridge): `fido2`, `cryptography`, `pyserial` — see `requirements.txt`

**C firmware** (Phase 2):
- [Pico SDK](https://github.com/raspberrypi/pico-sdk) — provides pico_stdlib, pico_rand, mbedtls (SHA-256, AES, HMAC)
- [micro-ecc](https://github.com/kmackay/micro-ecc) — vendored, ECDSA P-256 only
