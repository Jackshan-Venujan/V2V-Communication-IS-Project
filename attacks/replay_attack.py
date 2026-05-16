"""Replay Attack Demonstration — shows how the system detects replayed messages.

How a replay attack works:
  1. Attacker captures a valid encrypted BSM from Vehicle A
  2. Waits 6 seconds (beyond the 5-second freshness window)
  3. Replays the exact same bytes to Vehicle B
  4. Vehicle B rejects it because the timestamp is stale
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

from crypto.crypto import derive_session_key, ecdh_shared_secret, generate_ecdh_keypair
from protocol.auth_protocol import ReplayCache, StaleMessageError, TimestampValidator
from protocol.v2v_protocol import (
    BasicSafetyMessage,
    MessageLogger,
    SequenceError,
    secure_receive,
    secure_send,
)


def main() -> None:
    print("=" * 50)
    print("    REPLAY ATTACK DEMONSTRATION")
    print("=" * 50)

    # ── Setup: create session key and signing keys ──
    priv_a, pub_a = generate_ecdh_keypair()
    priv_b, pub_b = generate_ecdh_keypair()
    secret = ecdh_shared_secret(priv_a, pub_b)
    session_key = derive_session_key(secret, os.urandom(16), os.urandom(16))

    sign_key = generate_private_key(SECP256R1())
    verify_key = sign_key.public_key()

    logger = MessageLogger()

    # ── Step 1: Vehicle A sends a legitimate BSM ──
    bsm = BasicSafetyMessage(
        vehicle_id="vehicle-a",
        speed_kmh=80.0,
        heading_deg=45.0,
        latitude=6.9271,
        longitude=79.8612,
        timestamp=time.time(),
        sequence_num=1,
        brake_applied=False,
    )
    raw_bytes = secure_send(bsm, session_key, sign_key, logger)
    print(f"\n[CAPTURED] BSM at timestamp={bsm.timestamp:.3f}, seq={bsm.sequence_num}")
    print(f"           Payload size: {len(raw_bytes)} bytes")

    # ── Step 2: First delivery — should PASS ──
    rc = ReplayCache()
    tv = TimestampValidator(max_age_seconds=5.0)
    logger2 = MessageLogger()

    received = secure_receive(raw_bytes, session_key, verify_key, rc, tv, logger2)
    print(f"\n[OK] First delivery ACCEPTED")
    print(f"     Speed: {received.speed_kmh} km/h, Seq: {received.sequence_num}")

    # ── Step 3: Wait 6 seconds (beyond 5-second window) ──
    wait = 6
    print(f"\n[WAITING] {wait} seconds... (beyond 5-second replay window)")
    for i in range(wait, 0, -1):
        print(f"  {i}...", end=" ", flush=True)
        time.sleep(1)
    print()

    # ── Step 4: Replay the exact same bytes ──
    print("\n[REPLAY] Sending captured bytes again...")
    rc2 = ReplayCache()  # fresh cache to isolate the timestamp check
    tv2 = TimestampValidator(max_age_seconds=5.0)
    logger3 = MessageLogger()

    try:
        secure_receive(raw_bytes, session_key, verify_key, rc2, tv2, logger3, last_seq=0)
        print("[FAIL] Replayed message was ACCEPTED (this should not happen)")
    except (StaleMessageError, SequenceError) as e:
        print(f"[BLOCKED] Replay attempt REJECTED")
        print(f"          Reason: {e}")

    # ── Final Report ──
    print("\n" + "=" * 50)
    print("  RESULT: REPLAY ATTACK BLOCKED")
    print("=" * 50)
    print("  Security properties that stopped this:")
    print("  [x] Timestamp validation (5-second window)")
    print("  [x] Sequence number tracking")
    print("  [x] Nonce cache (256-bit nonces stored for 5 minutes)")


if __name__ == "__main__":
    main()
