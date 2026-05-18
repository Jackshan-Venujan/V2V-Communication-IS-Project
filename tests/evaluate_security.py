"""V2V Security Evaluation — benchmarks and metrics for design justification.

Measures encryption speed, signature speed, replay detection rate,
tamper detection rate, and nonce uniqueness. Outputs a formatted report
and saves results to tests/security_report.txt.
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

from crypto.crypto import (
    DecryptionError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ecdsa_sign,
    ecdsa_verify,
)
from protocol.auth_protocol import ReplayCache, ReplayError


def _header() -> str:
    return (
        "=" * 56 + "\n"
        "     V2V SECURITY EVALUATION REPORT\n"
        + "=" * 56
    )


def test_encryption_speed(iterations: int = 1000) -> dict:
    """Benchmark AES-256-GCM encryption throughput."""
    key = os.urandom(32)
    payload = b"test BSM payload " * 10  # ~170 bytes (realistic BSM size)

    start = time.perf_counter()
    for _ in range(iterations):
        aes_gcm_encrypt(key, payload)
    elapsed = time.perf_counter() - start

    ops = iterations / elapsed
    passed = ops > 500
    return {
        "name": "Encryption Speed",
        "result": f"{ops:.0f} ops/s",
        "target": ">500",
        "passed": passed,
    }


def test_decryption_speed(iterations: int = 1000) -> dict:
    """Benchmark AES-256-GCM decryption throughput."""
    key = os.urandom(32)
    payload = b"test BSM payload " * 10
    ct, nonce, tag = aes_gcm_encrypt(key, payload)

    start = time.perf_counter()
    for _ in range(iterations):
        aes_gcm_decrypt(key, ct, nonce, tag)
    elapsed = time.perf_counter() - start

    ops = iterations / elapsed
    passed = ops > 500
    return {
        "name": "Decryption Speed",
        "result": f"{ops:.0f} ops/s",
        "target": ">500",
        "passed": passed,
    }


def test_signature_speed(iterations: int = 100) -> dict:
    """Benchmark ECDSA P-256 signing throughput."""
    key = generate_private_key(SECP256R1())
    msg = b"test message for signing " * 5

    start = time.perf_counter()
    for _ in range(iterations):
        ecdsa_sign(key, msg)
    elapsed = time.perf_counter() - start

    ops = iterations / elapsed
    passed = ops > 100
    return {
        "name": "Signature Speed",
        "result": f"{ops:.0f} ops/s",
        "target": ">100",
        "passed": passed,
    }


def test_replay_detection(count: int = 100) -> dict:
    """Verify replay cache detects 100% of duplicate nonces."""
    cache = ReplayCache(window_seconds=300)

    # Add unique nonces
    nonces = [os.urandom(32).hex() for _ in range(count)]
    for n in nonces:
        cache.check_and_add(n)

    # Try re-adding each nonce — all should be rejected
    caught = 0
    for n in nonces:
        try:
            cache.check_and_add(n)
        except ReplayError:
            caught += 1

    passed = caught == count
    return {
        "name": "Replay Detection Rate",
        "result": f"{caught}/{count}",
        "target": "100%",
        "passed": passed,
    }


def test_tamper_detection(count: int = 50) -> dict:
    """Verify AES-GCM detects 100% of tampered ciphertexts."""
    key = os.urandom(32)
    caught = 0

    for _ in range(count):
        ct, nonce, tag = aes_gcm_encrypt(key, b"test BSM payload " * 10)
        # Flip one byte in the ciphertext
        tampered = bytearray(ct)
        if tampered:
            tampered[len(tampered) // 2] ^= 0x01
        try:
            aes_gcm_decrypt(key, bytes(tampered), nonce, tag)
        except DecryptionError:
            caught += 1

    passed = caught == count
    return {
        "name": "Tamper Detection Rate",
        "result": f"{caught}/{count}",
        "target": "100%",
        "passed": passed,
    }


def test_nonce_uniqueness(count: int = 10000) -> dict:
    """Verify os.urandom produces no collisions in N nonces."""
    nonces = set()
    for _ in range(count):
        nonces.add(os.urandom(32).hex())

    collisions = count - len(nonces)
    passed = collisions == 0
    return {
        "name": f"Nonce Uniqueness ({count//1000}k)",
        "result": f"{collisions} collisions",
        "target": "0",
        "passed": passed,
    }


def format_table(results: list[dict]) -> str:
    """Format results as a readable table."""
    lines = []
    lines.append("+" + "-" * 29 + "+" + "-" * 16 + "+" + "-" * 10 + "+" + "-" * 10 + "+")
    lines.append(f"| {'Test':<27} | {'Result':<14} | {'Target':<8} | {'Status':<8} |")
    lines.append("+" + "=" * 29 + "+" + "=" * 16 + "+" + "=" * 10 + "+" + "=" * 10 + "+")
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        lines.append(
            f"| {r['name']:<27} | {r['result']:<14} | {r['target']:<8} | {status:<8} |"
        )
    lines.append("+" + "-" * 29 + "+" + "-" * 16 + "+" + "-" * 10 + "+" + "-" * 10 + "+")

    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    lines.append(f"\nOverall: {passed}/{total} tests PASSED")
    return "\n".join(lines)


def main() -> None:
    print(_header())
    print()

    results = [
        test_encryption_speed(),
        test_decryption_speed(),
        test_signature_speed(),
        test_replay_detection(),
        test_tamper_detection(),
        test_nonce_uniqueness(),
    ]

    table = format_table(results)
    print(table)

    # Save to file
    report_path = Path(__file__).parent / "security_report.txt"
    with open(report_path, "w") as f:
        f.write(_header() + "\n\n")
        f.write(table + "\n")
        f.write(f"\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    main()
