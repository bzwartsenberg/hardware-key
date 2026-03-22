"""
Crypto layer for the FIDO U2F authenticator.

This module handles everything cryptographic:
- Device master secret (the root of trust)
- ECDSA P-256 key generation and signing
- Key wrapping (encrypting private keys into key handles)
- Self-signed attestation certificate

All FIDO authenticators must use ECDSA with the NIST P-256 curve
(also called secp256r1 or prime256v1 — three names for the same thing).
"""

import os
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime


# ---------------------------------------------------------------------------
# Device master secret
# ---------------------------------------------------------------------------
# This 32-byte random value is the root of all security. Every per-site
# private key is encrypted with a key derived from this secret.
#
# On a real device, this would be written to flash once during "first boot"
# and protected by hardware readback protection. Here it lives in memory —
# a new one is generated each time the authenticator starts, which means
# all previously registered credentials become invalid on restart.
# That's fine for learning.

def generate_master_secret() -> bytes:
    """Generate a 32-byte random master secret."""
    return os.urandom(32)


# ---------------------------------------------------------------------------
# Key wrapping — turning private keys into key handles and back
# ---------------------------------------------------------------------------
# The problem: we generate a unique private key per website, but we don't
# want to store them all. Solution: encrypt the private key with our master
# secret and hand the ciphertext (the "key handle") to the website.
#
# When the website asks us to authenticate later, it sends the key handle
# back. We decrypt it, recover the private key, sign the challenge, and
# forget the key again.
#
# We use AES-256-CBC with a random IV for encryption. The IV is prepended
# to the ciphertext. We also include an HMAC-SHA256 over the IV+ciphertext
# to detect tampering — without this, a corrupted or malicious key handle
# could cause us to operate on garbage data.
#
# Format of a key handle:
#   [16 bytes IV] [32 bytes ciphertext] [32 bytes HMAC]
#   = 80 bytes total
#
# Why AES-CBC and not something fancier like AES-GCM? Either works. SoloKeys
# uses CBC. GCM would combine encryption + authentication in one step, but
# CBC + HMAC is more educational — you can see both pieces separately.

# We derive two separate keys from the master secret: one for AES encryption,
# one for HMAC authentication. Using the same key for both would be a
# cryptographic sin — different operations need different keys.

def _derive_wrapping_keys(master_secret: bytes) -> tuple[bytes, bytes]:
    """
    Derive an AES key and an HMAC key from the master secret.

    We use HKDF-like derivation: HMAC the master secret with different
    labels to produce independent keys. This is a simplified version of
    HKDF-Expand — good enough for our purposes.
    """
    aes_key = hmac.new(master_secret, b"u2f-aes-key", hashlib.sha256).digest()
    hmac_key = hmac.new(master_secret, b"u2f-hmac-key", hashlib.sha256).digest()
    return aes_key, hmac_key


def wrap_key(master_secret: bytes, private_key_bytes: bytes) -> bytes:
    """
    Encrypt a 32-byte private key into a key handle.

    Steps:
    1. Derive AES and HMAC keys from the master secret
    2. Generate a random 16-byte IV (initialization vector) — this ensures
       that wrapping the same private key twice produces different ciphertexts
    3. Pad the private key to AES block size (16 bytes). Our input is 32 bytes
       which is already aligned, but PKCS7 padding adds a full block when the
       input is aligned — so the ciphertext will be 48 bytes. Actually, 32
       bytes is exactly 2 blocks, so PKCS7 adds 16 bytes of padding → 48 bytes.
       Wait — let me just use the padding properly and let it do its thing.
    4. Encrypt with AES-256-CBC
    5. HMAC the IV + ciphertext for integrity
    6. Return IV + ciphertext + HMAC tag
    """
    aes_key, hmac_key = _derive_wrapping_keys(master_secret)

    # Random IV — never reuse an IV with the same key
    iv = os.urandom(16)

    # PKCS7 padding: AES-CBC requires input to be a multiple of 16 bytes.
    # Our private key is 32 bytes (already aligned), but PKCS7 always adds
    # padding (a full block of 0x10 bytes when input is already aligned).
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(private_key_bytes) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # HMAC for integrity — covers both IV and ciphertext so neither
    # can be tampered with
    tag = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()

    return iv + ciphertext + tag


def unwrap_key(master_secret: bytes, key_handle: bytes) -> bytes | None:
    """
    Decrypt a key handle back into a 32-byte private key.

    Returns None if the HMAC check fails (tampered or wrong master secret).
    This is how the authenticator detects key handles that don't belong to it.
    """
    aes_key, hmac_key = _derive_wrapping_keys(master_secret)

    # Split the key handle into its components
    iv = key_handle[:16]
    tag = key_handle[-32:]
    ciphertext = key_handle[16:-32]

    # Verify HMAC first — ALWAYS verify before decrypting.
    # This is the "authenticate then decrypt" pattern. If we decrypted
    # first, we'd be operating on potentially tampered data.
    expected_tag = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        return None

    # Decrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    private_key_bytes = unpadder.update(padded) + unpadder.finalize()

    return private_key_bytes


# ---------------------------------------------------------------------------
# ECDSA P-256 — key generation and signing
# ---------------------------------------------------------------------------
# ECDSA (Elliptic Curve Digital Signature Algorithm) on the P-256 curve is
# the mandatory signature algorithm for FIDO. It gives us:
# - 32-byte private keys
# - 64-byte signatures (two 32-byte integers, r and s)
# - 65-byte uncompressed public keys (0x04 prefix + 32 bytes X + 32 bytes Y)
#
# The public key is a point on the P-256 elliptic curve. The private key is
# just a random 256-bit integer. The math guarantees you can derive the
# public key from the private key, but not the reverse.

def generate_key_pair() -> tuple[bytes, bytes]:
    """
    Generate a fresh ECDSA P-256 keypair.

    Returns:
        (private_key_bytes, public_key_bytes)
        - private_key_bytes: 32 bytes, the raw scalar
        - public_key_bytes: 65 bytes, uncompressed point (0x04 || x || y)

    The 0x04 prefix byte means "uncompressed point" — both X and Y
    coordinates are included. There's also a compressed format (33 bytes,
    just X + a sign bit) but FIDO uses uncompressed.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Extract the raw 32-byte private key scalar
    private_key_bytes = private_key.private_numbers().private_value.to_bytes(
        32, byteorder="big"
    )

    # Extract the uncompressed public key (65 bytes: 0x04 || x || y)
    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    return private_key_bytes, public_key_bytes


def private_key_from_bytes(private_key_bytes: bytes) -> ec.EllipticCurvePrivateKey:
    """
    Reconstruct a private key object from raw 32 bytes.

    We need this because after unwrapping a key handle, we have raw bytes
    but the cryptography library needs a key object to sign with.
    """
    private_value = int.from_bytes(private_key_bytes, byteorder="big")
    return ec.derive_private_key(private_value, ec.SECP256R1())


def sign(private_key_bytes: bytes, data: bytes) -> bytes:
    """
    Sign data with an ECDSA P-256 private key.

    Returns the signature in DER format, which is what U2F expects.

    DER encoding: the signature is two integers (r, s) encoded in ASN.1
    DER format. This is variable-length (70-72 bytes typically) unlike
    the fixed 64-byte "raw" format. U2F uses DER because that's what
    the original spec chose (inherited from older smart card standards).
    """
    key = private_key_from_bytes(private_key_bytes)
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """
    Verify an ECDSA P-256 signature. Used in testing.
    """
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_bytes
    )
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Attestation certificate
# ---------------------------------------------------------------------------
# During registration, the authenticator needs to sign the response with
# an "attestation key" and include the matching certificate. This tells the
# relying party what kind of authenticator produced the credential.
#
# For real authenticators (YubiKeys etc.), this cert chains back to the
# manufacturer's root CA, and the attestation private key is burned in
# during manufacturing.
#
# For us, it's self-signed. No relying party checks the chain for
# non-enterprise use, so this is perfectly functional.

def generate_attestation_cert() -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    """
    Generate a self-signed X.509 attestation certificate and its private key.

    Returns:
        (cert_der, private_key)
        - cert_der: the certificate in DER encoding (binary, not PEM)
        - private_key: the attestation signing key

    U2F expects DER-encoded certificates, not PEM. DER is the raw binary
    ASN.1 encoding; PEM is just base64-wrapped DER with header/footer lines.
    """
    # Generate the attestation keypair (separate from any per-site keys)
    private_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "DIY FIDO U2F Authenticator"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Homemade"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)  # same as subject → self-signed
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .sign(private_key, hashes.SHA256())
    )

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return cert_der, private_key
