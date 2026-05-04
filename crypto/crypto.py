"""Cryptographic helpers for the V2V security simulation.

This module groups the cryptographic operations used by the project in one
place: symmetric encryption, ECDH key exchange, ECDSA signing, and PEM
serialization helpers.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CryptoError(Exception):
    """Base exception for cryptographic errors in this simulation."""


class DecryptionError(CryptoError):
    """Raised when AES-GCM authentication fails during decryption."""


class SignatureError(CryptoError):
    """Raised when signature-related operations fail."""


def _ensure_bytes(value: bytes, name: str) -> None:
    """Validate that a value is a bytes object.

    Args:
        value: Value to validate.
        name: Human-readable name used in error messages.

    Raises:
        TypeError: If the value is not bytes.
    """

    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Args:
        key: A 32-byte AES-256 key.
        plaintext: Message bytes to encrypt.

    Returns:
        A tuple of ``(ciphertext, nonce, auth_tag)``.

    Raises:
        TypeError: If ``key`` or ``plaintext`` is not bytes.
        ValueError: If ``key`` is not exactly 32 bytes.
    """

    _ensure_bytes(key, "key")
    _ensure_bytes(plaintext, "plaintext")

    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes for AES-256-GCM")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted_blob = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = encrypted_blob[:-16]
    auth_tag = encrypted_blob[-16:]

    # The auth_tag is AES-GCM's built-in tamper detection.
    # If even one bit of ciphertext changes, decryption will fail.
    return ciphertext, nonce, auth_tag


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt AES-GCM ciphertext and verify message integrity.

    Args:
        key: A 32-byte AES-256 key.
        ciphertext: The encrypted message bytes.
        nonce: The 12-byte nonce used during encryption.
        tag: The 16-byte AES-GCM authentication tag.

    Returns:
        The original plaintext bytes.

    Raises:
        TypeError: If any argument is not bytes.
        ValueError: If the key, nonce, or tag lengths are invalid.
        DecryptionError: If authentication fails or the message was tampered with.
    """

    _ensure_bytes(key, "key")
    _ensure_bytes(ciphertext, "ciphertext")
    _ensure_bytes(nonce, "nonce")
    _ensure_bytes(tag, "tag")

    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes for AES-256-GCM")
    if len(nonce) != 12:
        raise ValueError("nonce must be exactly 12 bytes for AES-GCM")
    if len(tag) != 16:
        raise ValueError("tag must be exactly 16 bytes for AES-GCM")

    encrypted_blob = ciphertext + tag
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, encrypted_blob, None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Message authentication failed — possible tampering detected"
        ) from exc


def generate_ecdh_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a fresh ephemeral ECDH key pair for one session.

    Returns:
        A tuple of ``(private_key, public_key)`` on the NIST P-256 curve.
    """

    # We generate a NEW key pair each session (ephemeral).
    # This provides "Forward Secrecy": even if an old key leaks later,
    # past sessions can't be decrypted because this key no longer exists.
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def ecdh_shared_secret(
    my_private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    """Compute the ECDH shared secret with a peer public key.

    Args:
        my_private_key: The local ECDH private key.
        peer_public_key: The peer's ECDH public key.

    Returns:
        The raw shared secret bytes produced by ECDH.

    Raises:
        TypeError: If the provided keys are not elliptic-curve keys.
        CryptoError: If the exchange operation fails for any reason.
    """

    if not isinstance(my_private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("my_private_key must be an EllipticCurvePrivateKey")
    if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("peer_public_key must be an EllipticCurvePublicKey")

    try:
        return my_private_key.exchange(ec.ECDH(), peer_public_key)
    except Exception as exc:  # pragma: no cover - defensive wrapper
        raise CryptoError("failed to compute ECDH shared secret") from exc


def derive_session_key(shared_secret: bytes, nonce_a: bytes, nonce_b: bytes) -> bytes:
    """Derive a session key from an ECDH shared secret.

    Args:
        shared_secret: Raw ECDH output bytes.
        nonce_a: The first session nonce.
        nonce_b: The second session nonce.

    Returns:
        A 32-byte AES-256 session key.

    Raises:
        TypeError: If any argument is not bytes.
    """

    _ensure_bytes(shared_secret, "shared_secret")
    _ensure_bytes(nonce_a, "nonce_a")
    _ensure_bytes(nonce_b, "nonce_b")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce_a + nonce_b,
        info=b"v2v-session-key-v1",
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)


def ecdsa_sign(
    private_key: ec.EllipticCurvePrivateKey,
    message: bytes,
) -> bytes:
    """Create an ECDSA signature for a message.

    Args:
        private_key: The signing private key.
        message: Message bytes to sign.

    Returns:
        DER-encoded signature bytes.

    Raises:
        TypeError: If the private key or message has an invalid type.
    """

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("private_key must be an EllipticCurvePrivateKey")
    _ensure_bytes(message, "message")

    try:
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:  # pragma: no cover - defensive wrapper
        raise SignatureError("failed to create ECDSA signature") from exc


def ecdsa_verify(
    public_key: ec.EllipticCurvePublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    """Verify an ECDSA signature.

    Args:
        public_key: The public key used to verify the signature.
        message: The original message bytes.
        signature: DER-encoded signature bytes.

    Returns:
        ``True`` if the signature is valid, otherwise ``False``.

    Raises:
        TypeError: If the public key, message, or signature has an invalid type.
    """

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("public_key must be an EllipticCurvePublicKey")
    _ensure_bytes(message, "message")
    _ensure_bytes(signature, "signature")

    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def serialize_public_key(pub_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize a public key to PEM bytes.

    Args:
        pub_key: The elliptic-curve public key to serialize.

    Returns:
        PEM-encoded public key bytes.

    Raises:
        TypeError: If ``pub_key`` is not an elliptic-curve public key.
    """

    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        raise TypeError("pub_key must be an EllipticCurvePublicKey")

    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(pem_data: bytes) -> ec.EllipticCurvePublicKey:
    """Load a public key from PEM bytes.

    Args:
        pem_data: PEM-encoded public key bytes.

    Returns:
        The loaded elliptic-curve public key.

    Raises:
        TypeError: If ``pem_data`` is not bytes.
        ValueError: If the PEM data does not contain a valid public key.
    """

    _ensure_bytes(pem_data, "pem_data")

    try:
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend(),
        )
    except Exception as exc:
        raise ValueError("invalid PEM public key data") from exc

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("loaded key is not an elliptic-curve public key")

    return public_key


def load_private_key(pem_data: bytes) -> ec.EllipticCurvePrivateKey:
    """Load a private key from PEM bytes.

    Args:
        pem_data: PEM-encoded private key bytes.

    Returns:
        The loaded elliptic-curve private key.

    Raises:
        TypeError: If ``pem_data`` is not bytes.
        ValueError: If the PEM data does not contain a valid private key.
    """

    _ensure_bytes(pem_data, "pem_data")

    try:
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None,
            backend=default_backend(),
        )
    except Exception as exc:
        raise ValueError("invalid PEM private key data") from exc

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("loaded key is not an elliptic-curve private key")

    return private_key


if __name__ == "__main__":
    print("=== CRYPTO MODULE DEMONSTRATION ===")

    print("\n[TEST 1] ECDH Key Exchange")
    vehicle_a_private, vehicle_a_public = generate_ecdh_keypair()
    vehicle_b_private, vehicle_b_public = generate_ecdh_keypair()
    vehicle_a_secret = ecdh_shared_secret(vehicle_a_private, vehicle_b_public)
    vehicle_b_secret = ecdh_shared_secret(vehicle_b_private, vehicle_a_public)
    print(f"Vehicle A secret == Vehicle B secret: {vehicle_a_secret == vehicle_b_secret}")

    print("\n[TEST 2] Session Key Derivation")
    nonce_a = os.urandom(16)
    nonce_b = os.urandom(16)
    session_key = derive_session_key(vehicle_a_secret, nonce_a, nonce_b)
    print(f"Session key (hex): {session_key.hex()}")
    print(f"Session key length: {len(session_key)} bytes")

    print("\n[TEST 3] AES-GCM Encrypt/Decrypt")
    message = b"Hello from Vehicle A!"
    ciphertext, nonce, auth_tag = aes_gcm_encrypt(session_key, message)
    decrypted_message = aes_gcm_decrypt(session_key, ciphertext, nonce, auth_tag)
    print(f"Decrypted: {decrypted_message.decode('utf-8')} \u2713")

    print("\n[TEST 4] ECDSA Sign/Verify")
    signature = ecdsa_sign(vehicle_a_private, message)
    valid_signature = ecdsa_verify(vehicle_a_public, message, signature)
    invalid_signature = ecdsa_verify(vehicle_b_public, message, signature)
    print(f"Signature valid with matching key: {valid_signature}")
    print(f"Signature valid with wrong key: {invalid_signature}")

    print("\n[TEST 5] Tamper Detection")
    tamper_ciphertext, tamper_nonce, tamper_tag = aes_gcm_encrypt(session_key, message)
    tampered_ciphertext = bytearray(tamper_ciphertext)
    if tampered_ciphertext:
        tampered_ciphertext[0] ^= 0x01

    try:
        aes_gcm_decrypt(session_key, bytes(tampered_ciphertext), tamper_nonce, tamper_tag)
        print("Tampered message was not rejected")
    except DecryptionError:
        print("Tampered message correctly rejected \u2713")