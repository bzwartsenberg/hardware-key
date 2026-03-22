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
- Dependencies: `fido2`, `cryptography` (see `requirements.txt`)
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
# Serial monitor:
screen /dev/cu.usbmodem* 115200          # exit: Ctrl-A then \
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
│   └── fido_mbedtls_config.h # Minimal mbedtls config (SHA-256, AES, HMAC only)
├── src/
│   ├── main.c               # Authenticator firmware (placeholder)
│   ├── crypto.c             # ECDSA P-256 (micro-ecc), AES/HMAC (mbedtls)
│   └── test_crypto.c        # Crypto test + timing benchmarks
└── lib/
    └── micro-ecc/           # Vendored ECDSA library
```

## Key conventions
- All crypto uses ECDSA P-256 (secp256r1) as required by FIDO
- Key handles use AES-256-CBC wrapping with HMAC-SHA256 integrity
- Attestation cert is self-signed (fine for personal use)
- CTAPHID packets are always 64 bytes
