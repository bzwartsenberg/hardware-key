# CLAUDE.md — Hardware Key Project

## Project overview
DIY FIDO2/U2F hardware security key, eventually integrated into a custom mechanical keyboard.
See `FIDO2_HARDWARE_KEY_PROJECT.md` for the full project plan and protocol reference.

## Current phase
Phase 2: Port to RP2040 Pro Micro. C firmware, USB HID, on-device crypto.

## Teaching approach
This is a learning project. When writing code:
- Phase 1 (complete): focused on protocol and crypto concepts
- Phase 2 (current): focus on RP2040 setup, programming workflow, and microcontroller crypto
- Berend has strong AVR/C experience but is new to RP2040 and on-device crypto
- No need to re-explain FIDO protocol concepts unless the C implementation differs meaningfully

## Phase 1 — complete
Python U2F authenticator over UDP. Reference implementation.
```bash
source .venv/bin/activate
cd phase1-python-udp
python authenticator.py [--verbose]   # run authenticator (verbose shows all crypto steps)
python test_client.py                 # hand-rolled test with phishing detection
python test_fido2_client.py           # test using official python-fido2 library
```

## Development setup
- Python 3.11 (`python3.11` on system path), venv in `.venv/`
- Dependencies: `fido2`, `cryptography`, `pyserial` (see `requirements.txt`)
- Pico SDK at `~/pico-sdk`, env var `PICO_SDK_PATH` set in `~/.zshrc`
- ARM cross-compiler: `arm-none-eabi-gcc` (via Homebrew)
- micro-ecc vendored in `phase2-rp2040/lib/micro-ecc/`

## Phase 2 — building and flashing
```bash
cd phase2-rp2040/build
PICO_SDK_PATH=~/pico-sdk cmake ..    # configure (only needed after CMakeLists.txt changes)
make -j$(sysctl -n hw.ncpu)          # build both targets
# Flash: hold BOOTSEL + plug in, then:
cp authenticator.uf2 /Volumes/RPI-RP2/   # main firmware
cp test_crypto.uf2 /Volumes/RPI-RP2/     # crypto test with benchmarks
# Serial monitor (for test_crypto only):
screen /dev/cu.usbmodem* 115200          # exit: Ctrl-A then \
```

## Phase 2 — testing
The authenticator presents as a native USB HID device (FIDO usage page 0xF1D0).
Press BOOTSEL when LED blinks to approve register/authenticate requests.
```bash
# Native HID test (no bridge needed):
source .venv/bin/activate
python test_hid.py

# Legacy serial bridge test (requires re-enabling stdio_usb in CMakeLists.txt):
cd phase2-rp2040/bridge && python serial_bridge.py /dev/cu.usbmodem*
cd phase1-python-udp && python test_fido2_client.py
```

## Project structure
```
phase1-python-udp/           # Phase 1 — Python reference implementation
├── authenticator.py         # UDP server, CTAPHID + U2F logic, --verbose mode
├── crypto.py                # ECDSA P-256, AES key wrapping, attestation cert
├── test_client.py           # Hand-rolled test (raw packets, phishing test)
└── test_fido2_client.py     # Test using python-fido2 library (UDP adapter)

phase2-rp2040/               # Phase 2 — C firmware for RP2040
├── CMakeLists.txt           # Build config (authenticator + test_crypto targets)
├── include/
│   ├── crypto.h             # Crypto module interface
│   ├── ctaphid.h            # CTAPHID transport layer interface
│   ├── u2f.h                # U2F application layer interface
│   ├── storage.h            # Flash persistence interface
│   ├── button.h             # User presence (BOOTSEL button)
│   ├── tusb_config.h        # TinyUSB configuration (HID device, 64-byte reports)
│   └── fido_mbedtls_config.h # Minimal mbedtls config (SHA-256, AES, HMAC only)
├── src/
│   ├── main.c               # Authenticator firmware — USB HID event loop
│   ├── crypto.c             # ECDSA P-256 (micro-ecc), AES/HMAC (mbedtls)
│   ├── ctaphid.c            # CTAPHID packet framing and channel management
│   ├── u2f.c                # U2F register/authenticate + attestation cert
│   ├── storage.c            # Flash persistence (master secret + sign counter)
│   ├── button.c             # BOOTSEL button reading + LED feedback
│   ├── usb_descriptors.c   # USB device identity + TinyUSB callbacks
│   └── test_crypto.c        # Crypto test + timing benchmarks
├── bridge/
│   └── serial_bridge.py     # UDP <-> serial forwarder for testing
└── lib/
    └── micro-ecc/           # Vendored ECDSA library
```

## Key conventions
- All crypto uses ECDSA P-256 (secp256r1) as required by FIDO
- Key handles use AES-256-CBC wrapping with HMAC-SHA256 integrity
- Attestation cert is self-signed (fine for personal use)
- CTAPHID packets are always 64 bytes
- Authenticator firmware produces no text output — USB is HID-only (no serial)
- DEBUG_CRYPTO compile flag enables verbose crypto output (test_crypto target only)
- Master secret persists in flash — survives power cycles and reflash (UF2 bootloader doesn't erase storage sector)
- Sign counter uses log-structured flash writes (~1014 auths between erases)
- User presence requires BOOTSEL press; LED blinks during wait; KEEPALIVE packets sent to host
