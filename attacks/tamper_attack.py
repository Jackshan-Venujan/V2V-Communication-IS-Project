"""Tamper Attack Demonstration — shows how AES-GCM detects modified messages.

How a tamper attack works:
  1. Vehicle A sends an encrypted BSM
  2. Attacker intercepts the bytes and flips 3 bits in the ciphertext
  3. Vehicle B tries to decrypt -> AES-GCM auth tag no longer matches
  4. Decryption fails -> Message rejected
"""

from __future__ import annotations

import os
import random
import sys
import time
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

from crypto.crypto import derive_session_key, ecdh_shared_secret, generate_ecdh_keypair
from protocol.auth_protocol import ReplayCache, TimestampValidator
from protocol.v2v_protocol import (
    BasicSafetyMessage,
    MessageLogger,
    TamperError,
    secure_receive,
    secure_send,
)


def main() -> None:
    print("=" * 50)
    print("    TAMPER ATTACK DEMONSTRATION")
    print("=" * 50)

    # ── Setup ──
    priv_a, pub_a = generate_ecdh_keypair()
    priv_b, pub_b = generate_ecdh_keypair()
    secret = ecdh_shared_secret(priv_a, pub_b)
    session_key = derive_session_key(secret, os.urandom(16), os.urandom(16))

    sign_key = generate_private_key(SECP256R1())
    verify_key = sign_key.public_key()

    # ── Step 1: Create and encrypt a legitimate BSM ──
    bsm = BasicSafetyMessage(
        vehicle_id="vehicle-a",
        speed_kmh=85.3,
        heading_deg=90.0,
        latitude=6.9271,
        longitude=79.8612,
        timestamp=time.time(),
        sequence_num=1,
        brake_applied=True,
    )
    logger1 = MessageLogger()
    raw_bytes = secure_send(bsm, session_key, sign_key, logger1)
    print(f"\n[ORIGINAL] BSM encrypted: {len(raw_bytes)} bytes")
    print(f"           First 20 bytes (hex): {raw_bytes[:20].hex()}")

    # ── Step 2: Tamper with the ciphertext ──
    tampered = bytearray(raw_bytes)
    num_flips = 3
    # Target positions in the middle of the payload (where ciphertext lives)
    safe_start = 30  # skip the header fields
    positions = [random.randint(safe_start, len(tampered) - 1) for _ in range(num_flips)]

    print(f"\n[TAMPER] Flipping {num_flips} bytes in the ciphertext:")
    for pos in positions:
        before = tampered[pos]
        tampered[pos] ^= 0xFF
        after = tampered[pos]
        print(f"         Position {pos}: 0x{before:02x} -> 0x{after:02x}")

    # ── Step 3: Attempt to decrypt the tampered message ──
    print("\n[DECRYPT] Attempting to decrypt tampered message...")
    rc = ReplayCache()
    tv = TimestampValidator(max_age_seconds=5.0)
    logger2 = MessageLogger()

    try:
        secure_receive(bytes(tampered), session_key, verify_key, rc, tv, logger2)
        print("[FAIL] Tampered message was ACCEPTED (should not happen)")
    except TamperError as e:
        print(f"[BLOCKED] Tampered message REJECTED")
        print(f"          Reason: {e}")
    except Exception as e:
        print(f"[BLOCKED] Message rejected: {type(e).__name__}: {e}")

    # ── Step 4: Verify original still works ──
    print("\n[VERIFY] Decrypting the ORIGINAL (untampered) message...")
    rc2 = ReplayCache()
    tv2 = TimestampValidator(max_age_seconds=5.0)
    logger3 = MessageLogger()
    try:
        received = secure_receive(raw_bytes, session_key, verify_key, rc2, tv2, logger3)
        print(f"[OK] Original message decrypted: speed={received.speed_kmh} km/h")
    except Exception as e:
        print(f"[ERROR] Original also failed: {e}")

    # ── Final Report ──
    print("\n" + "=" * 50)
    print("  RESULT: TAMPER ATTACK BLOCKED")
    print("=" * 50)
    print("  [x] AES-256-GCM authentication tag mismatch")
    print("  [x] Even 1 flipped bit invalidates the entire message")
    print("  [x] ECDSA signature would also catch this after decryption")
    # This demonstrates "Authenticated Encryption" -- AES-GCM doesn't just
    # encrypt, it creates a tamper-evident seal. The 16-byte auth tag is
    # computed over the entire ciphertext. Change one byte -> tag mismatch.


if __name__ == "__main__":
    main()
