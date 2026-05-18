"""V2V message protocol — secure BSM creation, sending, and receiving.

This module implements the **Sign-then-Encrypt** pipeline:

  SEND: BSM -> ECDSA sign -> AES-256-GCM encrypt -> SecureBSM
  RECV: SecureBSM -> AES-GCM decrypt -> ECDSA verify -> BSM

Sign-then-Encrypt is chosen over Encrypt-then-Sign because signing the
plaintext prevents an attacker from stripping a signature off one
ciphertext and attaching it to another.
"""

from __future__ import annotations

import json
import logging
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# Ensure project root is on sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from crypto.crypto import (  # noqa: E402
    DecryptionError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ecdsa_sign,
    ecdsa_verify,
)
from protocol.auth_protocol import (  # noqa: E402
    ReplayCache,
    TimestampValidator,
)

LOGGER = logging.getLogger(__name__)


# ── Custom Exceptions ─────────────────────────────────────────────────────


class TamperError(Exception):
    """Message was modified in transit (AES-GCM tag mismatch or bad sig)."""


class ReplayError(Exception):
    """Duplicate message detected (same nonce or old timestamp)."""


class SequenceError(Exception):
    """Sequence number out of order — possible message suppression."""


# ── Data Classes ──────────────────────────────────────────────────────────


@dataclass
class BasicSafetyMessage:
    """The standard vehicle safety broadcast message (inspired by SAE J2735).

    In real V2V systems these are broadcast 10 times per second.
    In our simulation we send one per second.
    """

    vehicle_id: str
    speed_kmh: float
    heading_deg: float       # 0 = North, 90 = East
    latitude: float
    longitude: float
    timestamp: float
    sequence_num: int
    brake_applied: bool
    acceleration: float = 0.0

    def to_bytes(self) -> bytes:
        """Serialize to JSON bytes for signing / encryption."""
        return json.dumps(asdict(self)).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> BasicSafetyMessage:
        """Deserialize from JSON bytes."""
        return cls(**json.loads(data.decode("utf-8")))


@dataclass
class SecureBSM:
    """A BSM that has been signed and encrypted — the on-the-wire format.

    Structure: AES-GCM( BSM_bytes || ECDSA_signature )
    """

    ciphertext: bytes
    nonce: bytes          # 12-byte AES-GCM nonce
    auth_tag: bytes       # 16-byte AES-GCM tag
    sender_id: str
    sequence_num: int

    def to_bytes(self) -> bytes:
        """Pack into bytes for network transmission.

        Wire format:
          [sender_id_len:2][sender_id][seq:4][nonce:12][tag:16]
          [ct_len:4][ciphertext]
        """
        sid = self.sender_id.encode("utf-8")
        parts = [
            struct.pack(">H", len(sid)),
            sid,
            struct.pack(">I", self.sequence_num),
            self.nonce,    # always 12 bytes
            self.auth_tag, # always 16 bytes
            struct.pack(">I", len(self.ciphertext)),
            self.ciphertext,
        ]
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> SecureBSM:
        """Unpack from network bytes."""
        offset = 0

        sid_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        sender_id = data[offset : offset + sid_len].decode("utf-8")
        offset += sid_len

        seq = struct.unpack_from(">I", data, offset)[0]
        offset += 4

        nonce = data[offset : offset + 12]
        offset += 12

        tag = data[offset : offset + 16]
        offset += 16

        ct_len = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        ciphertext = data[offset : offset + ct_len]

        return cls(
            ciphertext=ciphertext,
            nonce=nonce,
            auth_tag=tag,
            sender_id=sender_id,
            sequence_num=seq,
        )


# ── Message Logger ────────────────────────────────────────────────────────


class MessageLogger:
    """Records sent/received messages with security status for the dashboard."""

    def __init__(self, max_messages: int = 50) -> None:
        self._messages: list[dict] = []
        self._alerts: list[dict] = []
        self._max = max_messages
        self.total_sent: int = 0
        self.total_received: int = 0
        self.tamper_blocked: int = 0
        self.replay_blocked: int = 0

    def log_sent(self, bsm: BasicSafetyMessage) -> None:
        """Log an outgoing BSM."""
        self.total_sent += 1
        entry = {
            "direction": "SENT",
            "time": time.strftime("%H:%M:%S"),
            "vehicle_id": bsm.vehicle_id,
            "speed": bsm.speed_kmh,
            "heading": bsm.heading_deg,
            "brake": bsm.brake_applied,
            "seq": bsm.sequence_num,
            "security": {
                "authenticated": True,
                "encrypted": True,
                "integrity_verified": True,
                "replay_protected": True,
            },
        }
        self._messages.append(entry)
        if len(self._messages) > self._max:
            self._messages.pop(0)

    def log_received(
        self, bsm: BasicSafetyMessage, security_props: dict
    ) -> None:
        """Log an incoming BSM with security verification results."""
        self.total_received += 1
        entry = {
            "direction": "RECV",
            "time": time.strftime("%H:%M:%S"),
            "vehicle_id": bsm.vehicle_id,
            "speed": bsm.speed_kmh,
            "heading": bsm.heading_deg,
            "brake": bsm.brake_applied,
            "seq": bsm.sequence_num,
            "security": security_props,
        }
        self._messages.append(entry)
        if len(self._messages) > self._max:
            self._messages.pop(0)

    def log_alert(self, alert_type: str, details: str) -> None:
        """Log a security alert."""
        if alert_type == "TAMPER":
            self.tamper_blocked += 1
        elif alert_type == "REPLAY":
            self.replay_blocked += 1

        self._alerts.append({
            "type": alert_type,
            "details": details,
            "time": time.strftime("%H:%M:%S"),
            "timestamp": time.time(),
        })

    def get_recent(self, count: int = 20) -> list[dict]:
        """Return the most recent N messages (newest first)."""
        return list(reversed(self._messages[-count:]))

    def get_alerts(self) -> list[dict]:
        """Return all security alerts."""
        return list(self._alerts)

    def clear_alerts(self) -> None:
        """Clear all alerts."""
        self._alerts.clear()


# ── Secure Send / Receive ─────────────────────────────────────────────────


def secure_send(
    bsm: BasicSafetyMessage,
    session_key: bytes,
    signing_key,           # ECDSA private key
    logger: MessageLogger,
) -> bytes:
    """Securely prepare a BSM for transmission (Sign-then-Encrypt).

    Steps:
      1. Serialize BSM to bytes
      2. ECDSA sign the plaintext bytes (non-repudiation)
      3. Combine BSM bytes + signature with length-prefix
      4. AES-256-GCM encrypt the combined payload (confidentiality)
      5. Build SecureBSM and return its wire bytes

    Args:
        bsm: The BasicSafetyMessage to send.
        session_key: 32-byte AES-256 session key from the handshake.
        signing_key: This vehicle's ECDSA private key.
        logger: MessageLogger to record the sent message.

    Returns:
        Wire-format bytes ready for ``send_framed()``.
    """
    # Step 1: serialize BSM to bytes
    bsm_bytes = bsm.to_bytes()

    # Step 2: sign the PLAINTEXT — proves content before encryption
    # Signing after encryption would let someone swap signatures between messages
    signature = ecdsa_sign(signing_key, bsm_bytes)

    # Step 3: combine with length-prefix for reliable unpacking
    # [4 bytes BSM length][BSM bytes][signature bytes]
    payload = struct.pack(">I", len(bsm_bytes)) + bsm_bytes + signature

    # Step 4: AES-256-GCM encrypt — confidentiality + integrity
    ciphertext, nonce, auth_tag = aes_gcm_encrypt(session_key, payload)

    # Step 5: wrap in SecureBSM
    secure = SecureBSM(
        ciphertext=ciphertext,
        nonce=nonce,
        auth_tag=auth_tag,
        sender_id=bsm.vehicle_id,
        sequence_num=bsm.sequence_num,
    )

    logger.log_sent(bsm)
    return secure.to_bytes()


def secure_receive(
    data: bytes,
    session_key: bytes,
    peer_verify_key,                       # ECDSA public key of sender
    replay_cache: ReplayCache,
    timestamp_validator: TimestampValidator,
    logger: MessageLogger,
    last_seq: Optional[int] = None,
) -> BasicSafetyMessage:
    """Receive, decrypt, verify, and parse a SecureBSM.

    Steps:
      1. Parse SecureBSM from raw bytes
      2. AES-GCM decrypt (integrity check via auth tag)
      3. Unpack plaintext into BSM bytes + signature
      4. ECDSA verify signature (authentication)
      5. Parse BSM and validate timestamp (replay prevention)

    Args:
        data: Raw bytes from ``recv_framed()``.
        session_key: 32-byte session key.
        peer_verify_key: Peer's ECDSA public key.
        replay_cache: ReplayCache instance.
        timestamp_validator: TimestampValidator instance.
        logger: MessageLogger for recording.
        last_seq: Last seen sequence number (or None).

    Returns:
        The verified BasicSafetyMessage.

    Raises:
        TamperError: If decryption fails or signature is invalid.
        SequenceError: If sequence number is not monotonically increasing.
    """
    # Step 1: parse SecureBSM
    secure = SecureBSM.from_bytes(data)

    # Step 2: AES-GCM decrypt — if even 1 bit was changed, this fails
    try:
        plaintext = aes_gcm_decrypt(
            session_key, secure.ciphertext, secure.nonce, secure.auth_tag
        )
    except DecryptionError as exc:
        logger.log_alert("TAMPER", f"AES-GCM decryption failed: {exc}")
        raise TamperError("Message tampered — AES-GCM auth tag mismatch") from exc

    # Step 3: unpack plaintext into BSM bytes + signature
    bsm_len = struct.unpack_from(">I", plaintext, 0)[0]
    bsm_bytes = plaintext[4 : 4 + bsm_len]
    signature = plaintext[4 + bsm_len :]

    # Step 4: verify ECDSA signature — proves the sender really signed this
    if not ecdsa_verify(peer_verify_key, bsm_bytes, signature):
        logger.log_alert("TAMPER", "ECDSA signature verification failed")
        raise TamperError("Invalid ECDSA signature — message not authentic")

    # Step 5: parse BSM and validate
    bsm = BasicSafetyMessage.from_bytes(bsm_bytes)

    # Check sequence number is increasing
    if last_seq is not None and bsm.sequence_num <= last_seq:
        logger.log_alert(
            "REPLAY",
            f"Seq {bsm.sequence_num} <= last {last_seq}",
        )
        raise SequenceError(
            f"Sequence {bsm.sequence_num} not greater than {last_seq}"
        )

    # Validate timestamp
    try:
        timestamp_validator.validate(bsm.timestamp)
    except Exception as exc:
        logger.log_alert("REPLAY", f"Stale timestamp: {exc}")
        raise

    # All checks passed — log with full security properties
    security_props = {
        "authenticated": True,
        "encrypted": True,
        "integrity_verified": True,
        "replay_protected": True,
    }
    logger.log_received(bsm, security_props)
    return bsm


# ── Demo ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    from crypto.crypto import generate_ecdh_keypair as _gen_kp
    from crypto.crypto import ecdh_shared_secret as _ecdh
    from crypto.crypto import derive_session_key as _derive

    print("=== V2V MESSAGE PROTOCOL DEMO ===\n")

    # Create a session key (simulating a completed handshake)
    priv_a, pub_a = _gen_kp()
    priv_b, pub_b = _gen_kp()
    secret = _ecdh(priv_a, pub_b)
    nonce_a, nonce_b = os.urandom(16), os.urandom(16)
    session_key = _derive(secret, nonce_a, nonce_b)
    print(f"Session key: {session_key.hex()[:32]}...")

    # Use Vehicle A's ECDH private key as signing key for demo
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    sign_priv = generate_private_key(SECP256R1())
    sign_pub = sign_priv.public_key()

    logger = MessageLogger()
    rc = ReplayCache()
    tv = TimestampValidator(max_age_seconds=5.0)

    # Create and send a BSM
    bsm = BasicSafetyMessage(
        vehicle_id="vehicle-a",
        speed_kmh=72.5,
        heading_deg=45.0,
        latitude=6.9271,
        longitude=79.8612,
        timestamp=time.time(),
        sequence_num=1,
        brake_applied=False,
        acceleration=1.2,
    )
    print(f"\n[SEND] BSM: speed={bsm.speed_kmh} km/h, seq={bsm.sequence_num}")

    wire_bytes = secure_send(bsm, session_key, sign_priv, logger)
    print(f"[WIRE] {len(wire_bytes)} bytes on the wire (encrypted)")

    # Receive and verify
    received = secure_receive(wire_bytes, session_key, sign_pub, rc, tv, logger)
    print(f"[RECV] BSM: speed={received.speed_kmh} km/h, seq={received.sequence_num}")
    print(f"[OK] All security checks passed!")

    # Tamper test
    print("\n--- TAMPER TEST ---")
    tampered = bytearray(wire_bytes)
    tampered[len(tampered) // 2] ^= 0xFF  # flip a byte
    try:
        secure_receive(bytes(tampered), session_key, sign_pub, rc, tv, logger, last_seq=0)
        print("[FAIL] Tampered message was accepted!")
    except TamperError as e:
        print(f"[OK] Tampered message REJECTED: {e}")

    print(f"\nStats: sent={logger.total_sent}, recv={logger.total_received}, "
          f"tamper_blocked={logger.tamper_blocked}")
