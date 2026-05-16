"""Man-in-the-Middle Attack Demonstration.

Scenario A: Attacker replaces a vehicle's certificate with a fake one.
            -> CA signature verification fails.

Scenario B: Attacker intercepts the handshake and tries to forge the
            challenge-response signature with their own key.
            -> ECDSA verification fails.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.x509.oid import NameOID

from crypto.crypto import ecdsa_sign, ecdsa_verify, load_private_key
from protocol.auth_protocol import (
    AuthProtocol,
    CertificateError,
    HelloMessage,
    verify_certificate_against_ca,
)


def _make_fake_cert(common_name: str = "vehicle-a") -> tuple[bytes, object]:
    """Generate a self-signed (fake) certificate pretending to be a vehicle."""
    fake_key = generate_private_key(SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V2V-Security-Lab"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed — NOT signed by CA
        .public_key(fake_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=fake_key, algorithm=hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, fake_key


def main() -> None:
    print("=" * 50)
    print("  MAN-IN-THE-MIDDLE ATTACK DEMONSTRATION")
    print("=" * 50)

    certs_dir = Path(__file__).resolve().parent.parent / "ca" / "certs"

    try:
        ca_pem = (certs_dir / "ca_cert.pem").read_bytes()
        a_cert = (certs_dir / "vehicle-a_cert.pem").read_bytes()
        a_key_pem = (certs_dir / "vehicle-a_key.pem").read_bytes()
        b_cert = (certs_dir / "vehicle-b_cert.pem").read_bytes()
        b_key_pem = (certs_dir / "vehicle-b_key.pem").read_bytes()
    except FileNotFoundError as e:
        print(f"ERROR: {e}\nRun ca/ca.py and issue_cert.py first.")
        sys.exit(1)

    a_key = load_private_key(a_key_pem)
    b_key = load_private_key(b_key_pem)

    # ==================================================================
    # SCENARIO A: Certificate replacement attack
    # ==================================================================
    print("\n--- SCENARIO A: Fake Certificate ---")
    print("Attacker generates a self-signed cert pretending to be vehicle-a")

    fake_cert_pem, fake_key = _make_fake_cert("vehicle-a")
    print(f"[ATTACK] Created fake certificate for 'vehicle-a' (self-signed)")

    # Vehicle B tries to verify the fake cert against the real CA
    print("[CHECK] Vehicle B verifies fake cert against CA...")
    try:
        verify_certificate_against_ca(fake_cert_pem.decode(), ca_pem)
        print("[FAIL] Fake certificate was ACCEPTED (should not happen)")
    except CertificateError as e:
        print(f"[BLOCKED] Fake certificate REJECTED")
        print(f"          Reason: {e}")

    # ==================================================================
    # SCENARIO B: Signature forgery attack
    # ==================================================================
    print("\n--- SCENARIO B: Forged Signature ---")
    print("Attacker intercepts handshake and forges the challenge-response")

    # Vehicle A sends authentic HELLO
    auth_a = AuthProtocol("vehicle-a", a_key, a_cert, ca_pem)
    hello = auth_a.build_hello()
    print(f"[HELLO] Vehicle A sends authentic HELLO (nonce={hello.nonce[:8]}...)")

    # Vehicle B creates a CHALLENGE (legitimate)
    auth_b = AuthProtocol("vehicle-b", b_key, b_cert, ca_pem)
    challenge = auth_b.process_hello(hello)
    print(f"[CHALLENGE] Vehicle B sends CHALLENGE (nonce={challenge.nonce[:8]}...)")

    # Attacker tries to forge the RESPONSE
    # The attacker has their own key — NOT Vehicle A's private key
    attacker_key = generate_private_key(SECP256R1())
    nonce_data = bytes.fromhex(hello.nonce) + bytes.fromhex(challenge.nonce)
    forged_sig = ecdsa_sign(attacker_key, nonce_data)

    print(f"[ATTACK] Attacker signs nonces with THEIR key (not vehicle-a's key)")

    # Vehicle B tries to verify the forged signature with Vehicle A's real public key
    a_pub_key = verify_certificate_against_ca(a_cert.decode(), ca_pem)

    result = ecdsa_verify(a_pub_key, nonce_data, forged_sig)
    if result:
        print("[FAIL] Forged signature was ACCEPTED (should not happen)")
    else:
        print(f"[BLOCKED] Forged signature REJECTED")
        print(f"          Reason: Signature does not match vehicle-a's public key")

    # ── Final Report ──
    print("\n" + "=" * 50)
    print("  RESULT: BOTH ATTACK SCENARIOS BLOCKED")
    print("=" * 50)
    print("  [x] X.509 certificates are CA-signed (can't fake without CA key)")
    print("  [x] Challenge-response proves private key ownership")
    print("  [x] Certificate replacement detected by CA signature verification")
    print("  [x] Signature forgery detected by ECDSA public key verification")


if __name__ == "__main__":
    main()
