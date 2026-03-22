# DIY FIDO2 Hardware Security Key — Project Plan

## Overview

Build a FIDO2/U2F hardware security key that can eventually be integrated into a custom mechanical keyboard. The authenticator implements the FIDO Alliance's CTAP protocol, performing ECDSA P-256 challenge-response signing with a device-resident private key. The end goal is a USB composite device that presents both keyboard HID and FIDO HID interfaces from a single MCU and USB cable.

## Background & Motivation

- I build custom mechanical keyboards (QMK on ATmega, ZMK on nRF52840).
- A keyboard is already a USB HID device with a microcontroller and flash storage — it can also serve as a hardware security key.
- The private key never leaves the device during normal FIDO2 operation. Security against remote attackers is equivalent to a YubiKey. Physical-access security is bounded by flash readback protection (e.g., APPROTECT on nRF52840, or equivalent on RP2040), which is sufficient for realistic threat models (not defending against state-level attackers with chip decapping equipment).
- For theft protection, CTAP2 includes a PIN mechanism (clientPIN protocol) with hardware-enforced rate limiting (8 wrong attempts → wipe). This is a later enhancement.

## How FIDO2 / U2F Works (Reference)

### Protocol Stack
```
Browser/OS (WebAuthn API)
    ↕
CTAP2/CTAP1 application protocol (CBOR or raw messages)
    ↕
CTAPHID transport (64-byte HID report framing)
    ↕
USB HID (usage page 0xF1D0)
    ↕
Hardware (MCU with crypto + flash storage)
```

### Registration Flow
1. Relying party (website) sends a challenge + origin hash.
2. Authenticator generates a per-site ECDSA P-256 keypair.
3. Private key is wrapped (encrypted) with a device master secret and returned as a "key handle." This avoids needing per-site storage.
4. Public key + key handle + attestation signature are returned.
5. Relying party stores the public key and key handle.

### Authentication Flow
1. Relying party sends challenge + origin hash + key handle.
2. Authenticator unwraps the key handle to recover the private key.
3. Authenticator verifies origin hash matches (phishing protection).
4. Authenticator increments a monotonic counter (clone detection).
5. Authenticator signs (origin hash || presence byte || counter || challenge).
6. Relying party verifies signature with stored public key.

### Key Security Properties
- Private key never exported — generated on-device, used only for signing.
- User presence required — button press proves a human is there.
- Phishing resistant — origin is cryptographically bound into the signature.
- Counter detects cloning — if counter goes backwards, something is wrong.

### CTAP2 PIN (Later Enhancement)
- PIN set on first use (4–63 chars), verified on-device before signing.
- 8 consecutive wrong attempts → device locks and wipes all credentials.
- PIN is not the decryption key for credentials — it's an access gate.
- PIN is encrypted in transit via ECDH key agreement (protects against USB sniffing).

## Target Hardware

### Primary: Raspberry Pi Pico (RP2040)
- Dual-core Cortex-M0+ at 133 MHz
- 264 KB SRAM, 2 MB flash
- Native USB 1.1 with TinyUSB support (included in Pico SDK)
- No hardware crypto accelerator, but fast enough for software ECDSA (~50–100ms per sign)
- No hardware RNG, but ring oscillator jitter + key timing entropy is sufficient
- Available now for prototyping

### Alternative: nRF52840 (for ZMK integration path)
- Cortex-M4F at 64 MHz
- 1 MB flash, 256 KB SRAM
- CryptoCell 310 hardware crypto accelerator
- Native USB + BLE
- This is the exact chip Google's OpenSK targets
- Good option if integrating alongside a ZMK keyboard build
- Available as bare modules (Holyiot 18010, ~$5) or dev boards (nice!nano, Nordic dongle)
- OpenSK runs on it essentially out of the box

### Not Recommended: ATmega32U4 (Arduino Pro Micro)
- 32 KB flash, 2.5 KB SRAM — QMK alone uses 20–28 KB flash
- 8-bit AVR makes P-256 ECDSA very slow (~1–2 seconds per sign at 16 MHz)
- Extremely tight on RAM for simultaneous QMK + crypto working memory
- No hardware RNG (solvable but annoying)
- Possible as a challenge project, not pragmatic

## Development Phases

### Phase 1: Python UDP Authenticator (Laptop Only)

**Goal**: Learn the CTAPHID transport and U2F protocol without any hardware or USB complexity.

**How it works**: The FIDO HID protocol is just 64-byte packets. Instead of USB, send them over UDP datagrams on localhost. Yubico's `python-fido2` library supports a virtual UDP transport. SoloKeys and Nitrokey firmware both use this same pattern for development.

**Implementation**:
- Python script listening on UDP port 7112 (conventional FIDO virtual device port).
- Implements CTAPHID framing: INIT, MSG, ERROR, KEEPALIVE commands.
- Implements U2F_REGISTER and U2F_AUTHENTICATE inside MSG commands.
- Uses `python-ecdsa` or `cryptography` library for P-256 ECDSA.
- Master secret is just a random bytes object in memory (no persistence needed yet).
- Test with `python-fido2` example client configured for UDP transport.

**Project structure**:
```
phase1-python-udp/
├── authenticator.py      # UDP server, CTAPHID + U2F logic
├── crypto.py             # ECDSA P-256 wrappers, key wrapping
├── test_client.py        # Simple test using python-fido2
└── requirements.txt      # python-fido2, cryptography
```

**Milestones**:
1. CTAPHID INIT handshake works (channel allocation).
2. U2F_REGISTER returns a valid public key + key handle + attestation cert.
3. U2F_AUTHENTICATE signs a challenge and the client verifies it.
4. Full round-trip: register, then authenticate with the key handle from registration.

**Key details to get right**:
- CTAPHID packet format: 4-byte channel ID, 1-byte command, 2-byte payload length, then payload bytes. Packets are 64 bytes; longer messages are fragmented with continuation packets (high bit of command byte clear).
- Broadcast channel for INIT is 0xFFFFFFFF.
- U2F registration response format: `0x05 || pubkey (65 bytes uncompressed) || key_handle_len (1 byte) || key_handle || X.509 attestation cert || signature`.
- Key handle = encrypt(private_key, device_master_secret). Can use AES-256-CBC or HMAC-based wrapping.
- Attestation cert can be self-signed — for personal use nobody checks the chain.
- Sign-counter starts at 0, increments on each authenticate.

### Phase 2: C on RP2040 over Serial

**Goal**: Validate the C implementation and crypto on real hardware, without dealing with USB HID enumeration.

**How it works**: The RP2040 runs the authenticator firmware in C. It communicates over USB CDC serial (which the Pico SDK supports trivially with `pico_stdio_usb`). A thin Python bridge on the laptop shuttles 64-byte packets between `python-fido2` (UDP) and the serial port.

**Implementation**:
- Port the authenticator logic from Phase 1 to C.
- Use micro-ecc (`uECC.c` / `uECC.h`) for ECDSA P-256 — single-file library.
- Use mbedtls (included in Pico SDK as `pico_mbedtls`) for SHA-256, or a standalone implementation.
- RNG: implement `uECC_rng_function` callback using Pico SDK's `get_rand_32()` (ring oscillator jitter). For better entropy, also accumulate from a floating ADC pin.
- Store master secret + sign counter in a reserved flash sector using `flash_range_program` / `flash_range_erase`.
- Wire up a button for user presence (or use BOOTSEL on Pico for testing).
- Python bridge on laptop: ~30 lines, opens serial port + UDP socket, forwards 64-byte packets.

**Project structure**:
```
phase2-rp2040-serial/
├── CMakeLists.txt
├── src/
│   ├── main.c              # Init, main loop, serial I/O
│   ├── ctaphid.c           # Transport layer framing (same as Phase 1 logic)
│   ├── u2f.c               # U2F register/authenticate
│   ├── crypto.c            # micro-ecc + SHA-256 wrappers
│   ├── storage.c           # Flash read/write for master secret + counter
│   └── button.c            # User presence GPIO
├── lib/
│   └── micro-ecc/          # Dropped in
├── include/
│   └── *.h
└── bridge/
    └── serial_bridge.py    # Laptop-side UDP↔serial bridge
```

**Serial transport detail**: CDC serial is a byte stream, not a packet protocol. Since CTAPHID packets are always exactly 64 bytes, always read/write exactly 64 bytes. No additional framing needed — the fixed size provides implicit boundaries.

**Milestones**:
1. RP2040 boots, serial connection established, can send/receive 64-byte packets.
2. CTAPHID INIT works over serial bridge.
3. U2F_REGISTER succeeds — crypto runs correctly on Cortex-M0+.
4. Master secret persists across reboots (flash storage works).
5. Sign counter increments and persists.
6. Button press gates signing (user presence).

### Phase 3: USB FIDO HID on RP2040 (Standalone Authenticator)

**Goal**: Replace serial transport with native USB FIDO HID. The RP2040 now appears as a real FIDO security key to the OS/browser.

**Implementation**:
- Add FIDO HID interface using TinyUSB (included in Pico SDK).
- HID report descriptor: 64-byte input reports, 64-byte output reports, usage page 0xF1D0, usage 0x01. The FIDO HID report descriptor is standardized by the FIDO Alliance.
- Application code from Phase 2 carries over unchanged — only the transport layer changes (serial recv/send → TinyUSB HID report callbacks).
- TinyUSB callbacks: `tud_hid_set_report_cb` for receiving packets from host, `tud_hid_report` for sending responses.

**USB descriptor**: Single-interface device at this stage. The device descriptor + configuration descriptor + HID interface descriptor + FIDO HID report descriptor. TinyUSB has examples for custom HID devices.

**Milestones**:
1. Device enumerates as FIDO HID — `lsusb -v` on Linux shows usage page 0xF1D0. Chrome's `chrome://device-log` detects it.
2. Chrome shows "Touch your security key" when WebAuthn is triggered — proves CTAPHID INIT works over real USB.
3. Full U2F registration + authentication works from `python-fido2` (using HID transport now, not UDP).
4. Register with GitHub or Google as a security key.

**Linux udev note**: Standard FIDO udev rules match on the usage page, so if the descriptor is correct, the device should be accessible without root. The standard rules file is `70-u2f.rules` (from the `libu2f-udev` package or Yubico's repo).

### Phase 4: USB Composite Device (Keyboard + FIDO)

**Goal**: Single RP2040 runs QMK keyboard + FIDO authenticator. One chip, one USB cable, one device.

**Implementation options**:

**Option A: QMK + custom FIDO HID interface (recommended)**
- QMK already uses TinyUSB on RP2040 and supports composite USB descriptors (keyboard + mouse + raw HID).
- Add the FIDO HID interface as another interface in the composite descriptor.
- Run FIDO logic in the main loop alongside QMK's matrix scanning.
- ECDSA signing (~50–100ms) may block matrix scanning briefly — acceptable, or use RP2040's second core.

**Option B: Dual-core split**
- Core 0: QMK keyboard firmware.
- Core 1: FIDO authenticator logic.
- Shared TinyUSB stack (TinyUSB is not thread-safe by default — need careful synchronization via Pico SDK multicore primitives like `multicore_fifo`).
- More complex but guarantees no input latency during signing.

**User presence**: Any keypress within a timeout window, or a designated key/combo. The "touch your security key" browser prompt maps naturally to typing.

**Milestones**:
1. Composite USB descriptor enumerates correctly — OS sees both keyboard HID and FIDO HID.
2. Keyboard works normally while FIDO is idle.
3. FIDO registration/authentication works while keyboard is also functional.
4. No dropped keypresses during ECDSA signing.

### Phase 4-Alt: Separate Chip on Keyboard PCB

**Goal**: If composite firmware is too complex, or for the nRF52840/ZMK path, use a dedicated FIDO chip alongside the keyboard MCU, sharing one USB cable via an on-board USB hub.

**Hub chip**: FE1.1s (~$0.50), 2-port USB 2.0 hub. Minimal external components (crystal, caps).

**PCB layout**:
```
USB-C connector → FE1.1s hub → Downstream port 1 → Keyboard MCU (ATmega/RP2040/nRF)
                              → Downstream port 2 → FIDO MCU (nRF52840 or second RP2040)
```

**For the nRF52840 path**: Flash OpenSK onto a bare nRF52840 module. It runs entirely independently. No firmware interaction with the keyboard MCU at all. BOM cost increase: ~$5 for the module + ~$0.50 for the hub chip.

**For testing before PCB design**: Flash OpenSK onto a Nordic nRF52840 dongle ($10) or Adafruit Feather nRF52840 and use it standalone to validate the concept. Then allocate a footprint on your keyboard PCB.

## Libraries & Dependencies

### Python (Phase 1)
- `python-fido2` (Yubico) — FIDO2 client library, supports UDP virtual device transport
- `cryptography` — ECDSA P-256, SHA-256, AES for key wrapping

### C (Phase 2+)
- **micro-ecc** — Single-file ECDSA P-256 implementation (uECC.c + uECC.h). ~5–8 KB code, ~1 KB working RAM.
- **mbedtls** — SHA-256, AES (included in Pico SDK as `pico_mbedtls`). Or use a standalone SHA-256.
- **Pico SDK** — USB (TinyUSB), flash programming, GPIO, stdio.
- **TinyUSB** — USB HID stack, composite device support (included in Pico SDK).

### Reference Firmware (for code study, not direct porting)
- **SoloKeys solo1** — C, STM32-based, implements CTAP2. Crypto and protocol logic are relatively self-contained. Good reference for key wrapping, attestation, and U2F message parsing.
- **Google OpenSK** — Rust + Zephyr, targets nRF52840. Best reference for the nRF path.
- **Nitrokey FIDO2** — Fork of SoloKeys, also C/STM32. Includes UDP development mode.

## Flash Storage Layout (RP2040)

Reserve the last few sectors of flash for authenticator data:

```
Sector N-2:  Device master secret (32 bytes) + attestation private key (32 bytes)
             Written once on first boot. Protected by flash readback protection.
Sector N-1:  Sign counter (4 bytes, monotonically increasing)
             Updated on each authentication. Consider wear leveling for longevity
             (write to next slot in sector, erase when full — ~100K erases per sector,
             so with 4-byte counter and 4096-byte sector, that's ~100M authentications
             before needing to think about it).
Sector N:    Resident key storage (CTAP2 only, Phase 5+)
             Key-value store for discoverable credentials.
```

## Crypto Notes

- **ECDSA P-256 (secp256r1)**: Mandatory for FIDO. 32-byte private keys, 64-byte signatures, 65-byte uncompressed public keys (or 33-byte compressed). Chosen for small key/signature size — matters on constrained MCUs.
- **Key wrapping**: The device master secret is used to deterministically derive or encrypt per-site private keys from key handles. This means the device doesn't need per-site storage (the key handle is stored by the relying party and sent back during authentication). SoloKeys uses AES-256-CBC; HMAC-based key derivation (HKDF with the key handle as input) also works.
- **Attestation**: During registration, the authenticator signs the response with an attestation key + cert that vouches for the authenticator's identity. For personal use, a self-signed cert is fine. The FIDO metadata service and green checkmarks only matter for enterprise deployments.
- **RNG on RP2040**: Seed a DRBG (e.g., CTR-DRBG from mbedtls) with entropy from ring oscillator (`get_rand_32()`), floating ADC pin noise, and key timing jitter. The keyboard use case is actually ideal for entropy — every keypress is an entropy event.

## Testing Tools

- **python-fido2**: `pip install fido2`. Includes example scripts for registration/authentication. Supports USB HID, UDP virtual device, and can be extended for serial.
- **Chrome DevTools**: `chrome://device-log` shows FIDO device detection. `chrome://webauthn` has a built-in test interface.
- **Linux**: `lsusb -v` to inspect USB descriptors. Standard udev rules (`70-u2f.rules`) for non-root access.
- **webauthn.io**: Web-based test relying party for end-to-end testing.
- **GitHub**: Supports U2F security keys under Settings → Security → Two-factor authentication.

## Security Considerations

- **Flash readback protection**: Enable on the RP2040 before considering this production-ready. Without it, anyone with physical access and a debugger can dump flash.
- **Side-channel attacks**: Software ECDSA on a general-purpose MCU is theoretically vulnerable to timing and power analysis. For a personal security key this is not a realistic concern. If it ever matters, constant-time implementations exist (e.g., tinycrypt).
- **Cloning**: The monotonic counter detects if a key handle is used on two devices. The relying party should reject authentications where the counter doesn't increase.
- **Loss/theft without PIN**: Without CTAP2 PIN, anyone with the device can authenticate (assuming they also know username + password, since FIDO is 2FA). Adding PIN support (Phase 5) addresses this.

## Future Enhancements (Phase 5+)

- **CTAP2 / Full FIDO2**: PIN support, resident/discoverable keys (passkeys), authenticatorGetInfo, CBOR encoding. Significantly more code (~2000–4000 lines) but enables passwordless login.
- **BLE transport**: FIDO2 over BLE (caBLE/hybrid protocol). Complex but possible on nRF52840. Not practical on RP2040 (no BLE).
- **OpenPGP / SSH signing**: Use the same key storage and crypto to also function as a GPG smartcard or SSH key. Different USB interface (CCID) but same MCU.
- **Backup/recovery**: Derive all per-site keys from the master secret deterministically. If you build two identical devices with the same master secret, they function as backups of each other. (This technically violates the "no cloning" principle, but for personal use it's a pragmatic recovery strategy.)
