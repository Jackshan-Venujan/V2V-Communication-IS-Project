"""Verify vehicle certificates for the V2V security simulation."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509.oid import NameOID


# Parse command-line arguments so users can choose which certificate to verify.
def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for certificate verification.

    Returns:
        argparse.Namespace: Parsed values for --cert and --ca-cert.
    """

    parser = argparse.ArgumentParser(
        description="Verify a vehicle certificate against a trusted CA certificate."
    )
    parser.add_argument(
        "--cert",
        required=True,
        help="Path to the vehicle certificate to verify, for example: ca/certs/vehicle-a_cert.pem",
    )
    parser.add_argument(
        "--ca-cert",
        required=True,
        help="Path to the trusted CA certificate, for example: ca/certs/ca_cert.pem",
    )
    return parser.parse_args()


# Load a PEM certificate from disk so it can be checked.
def load_certificate(cert_path: Path) -> x509.Certificate:
    """Load an X.509 certificate from a PEM file.

    Args:
        cert_path: Path to the PEM certificate file.

    Returns:
        x509.Certificate: Parsed certificate object.
    """

    try:
        if not cert_path.exists():
            raise FileNotFoundError(f"Certificate file not found: {cert_path}")
        cert_bytes = cert_path.read_bytes()
        return x509.load_pem_x509_certificate(cert_bytes)
    except Exception as exc:
        raise RuntimeError(f"Failed to load certificate '{cert_path}': {exc}") from exc


# Read validity dates in UTC while supporting older and newer cryptography APIs.
def get_validity_window(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    """Return certificate validity range as timezone-aware UTC datetimes.

    Args:
        certificate: Certificate to inspect.

    Returns:
        tuple[datetime, datetime]: Not-before and not-after timestamps in UTC.
    """

    not_before = getattr(certificate, "not_valid_before_utc", None)
    not_after = getattr(certificate, "not_valid_after_utc", None)

    if not_before is None:
        not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)

    return not_before, not_after


# Verify the certificate signature to confirm the trusted CA actually signed it.
def check_signature(
    certificate: x509.Certificate,
    ca_certificate: x509.Certificate,
) -> tuple[bool, str]:
    """Verify certificate signature with the CA public key.

    Args:
        certificate: Vehicle certificate being verified.
        ca_certificate: Trusted CA certificate used to verify signature.

    Returns:
        tuple[bool, str]: Success flag and human-readable message.
    """

    try:
        ca_public_key = ca_certificate.public_key()
        if not isinstance(ca_public_key, EllipticCurvePublicKey):
            return False, "[FAIL] Signature invalid - CA public key is not ECDSA."

        # Signature verification checks if this cert was truly signed by our trusted CA.
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )

        issuer_cn = ca_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_name = issuer_cn[0].value if issuer_cn else "trusted CA"
        return True, f"[OK] Signature valid - signed by {issuer_name}"
    except InvalidSignature:
        return False, "[FAIL] Signature invalid - NOT signed by trusted CA"
    except Exception as exc:
        return False, f"[FAIL] Signature check error - {exc}"


# Check whether the certificate is currently inside its valid date window.
def check_dates(certificate: x509.Certificate) -> tuple[bool, str]:
    """Check whether certificate validity dates include current time.

    Args:
        certificate: Certificate being verified.

    Returns:
        tuple[bool, str]: Success flag and human-readable message.
    """

    try:
        now = datetime.now(timezone.utc)
        not_before, not_after = get_validity_window(certificate)

        # Date validation blocks certificates that are expired or not valid yet.
        if now < not_before:
            return False, (
                f"[FAIL] Date invalid - certificate not valid until {not_before.date()}"
            )
        if now > not_after:
            return False, f"[FAIL] Date invalid - expired on {not_after.date()}"

        return True, f"[OK] Date valid - expires {not_after.date()}"
    except Exception as exc:
        return False, f"[FAIL] Date check error - {exc}"


# Display who this certificate belongs to by reading subject fields.
def check_subject(certificate: x509.Certificate) -> tuple[bool, str]:
    """Extract and report certificate subject information.

    Args:
        certificate: Certificate being verified.

    Returns:
        tuple[bool, str]: Success flag and human-readable message.
    """

    try:
        subject_text = certificate.subject.rfc4514_string()
        if not subject_text:
            return False, "[FAIL] Subject missing - certificate has no subject name"
        return True, f"[OK] Subject: {subject_text}"
    except Exception as exc:
        return False, f"[FAIL] Subject check error - {exc}"


# Run all verification checks and return shell-friendly exit codes.
def verify_certificate() -> int:
    """Verify a certificate against a trusted CA certificate.

    Returns:
        int: 0 when certificate is valid, 1 when invalid.
    """

    try:
        args = parse_args()
        cert_path = Path(args.cert)
        ca_cert_path = Path(args.ca_cert)

        # Announce the certificate currently under verification.
        print(f"[CHECKING] {cert_path.as_posix()}")

        # Load both certificates so we can compare issuer signature and metadata.
        certificate = load_certificate(cert_path)
        ca_certificate = load_certificate(ca_cert_path)

        # Run signature check, which proves trust from the CA.
        sig_ok, sig_msg = check_signature(certificate, ca_certificate)
        print(sig_msg)

        # Run date check, which ensures the cert is not expired or early.
        date_ok, date_msg = check_dates(certificate)
        print(date_msg)

        # Run subject check, which tells us which vehicle owns this cert.
        subject_ok, subject_msg = check_subject(certificate)
        print(subject_msg)

        # Decide the final verification result from all checks.
        if sig_ok and date_ok and subject_ok:
            print("RESULT: CERTIFICATE IS VALID")
            return 0

        print("RESULT: CERTIFICATE IS INVALID")
        return 1
    except Exception as exc:
        print(f"[FAIL] Verification error - {exc}")
        print("RESULT: CERTIFICATE IS INVALID")
        return 1


if __name__ == "__main__":
    # Execute verification when this file is run from the command line.
    raise SystemExit(verify_certificate())