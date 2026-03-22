# CLAUDE.md — Hardware Key Project

## Project overview
DIY FIDO2/U2F hardware security key, eventually integrated into a custom mechanical keyboard.
See `FIDO2_HARDWARE_KEY_PROJECT.md` for the full project plan and protocol reference.

## Current phase
Phase 1: Python UDP authenticator (laptop only). Learning project — understanding the protocols and crypto.

## Teaching approach
This is a learning project. When writing code:
- Point out relevant functions and explain what they do
- Explain the cryptography: what's being signed, why, and how it fits the FIDO2 security model
- Connect code to protocol concepts (CTAPHID framing, U2F message format, key wrapping, etc.)
- Explanations can be inline during coding or as a summary after

## Development setup
- Python 3.11 (`python3.11` on system path), venv in `.venv/` — activate with `source .venv/bin/activate`
- Dependencies: `fido2`, `cryptography` (see `requirements.txt`)
- Target: UDP virtual FIDO device on localhost:7112

## Project structure (Phase 1)
```
phase1-python-udp/
├── authenticator.py      # UDP server, CTAPHID + U2F logic
├── crypto.py             # ECDSA P-256 wrappers, key wrapping
├── test_client.py        # Test using python-fido2
└── requirements.txt      # (root level)
```

## Commands
```bash
source .venv/bin/activate           # activate venv
python phase1-python-udp/authenticator.py  # run the authenticator
python phase1-python-udp/test_client.py    # run tests against it
```

## Key conventions
- All crypto uses ECDSA P-256 (secp256r1) as required by FIDO
- Key handles use AES-256 wrapping of per-site private keys with device master secret
- Attestation cert is self-signed (fine for personal use)
- CTAPHID packets are always 64 bytes, sent over UDP on port 7112
