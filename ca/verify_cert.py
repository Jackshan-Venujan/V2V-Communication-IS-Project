"""Certificate verifier for the V2V security simulation.

This module checks that a vehicle certificate is signed by the configured CA
and that the certificate is currently within its validity period.
"""

from __future__ import annotations

import argparse
import logging
import os
from datetime import timezone

UTC = timezone.utc

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa


LOGGER = logging.getLogger(__name__)
DEFAULT_CA_CERT_PATH = os.path.join("ca", "certs", "ca_cert.pem")


def configure_logging() -> None:
    """Configure timestamped logging for verification operations.

    Returns:
        None: This function only configures the Python logging subsystem.
    """

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for certificate verification.

    Returns:
        An argparse namespace containing the requested values.
    """

    parser = argparse.ArgumentParser(description="Verify a V2V vehicle certificate")
    parser.add_argument("--cert", required=True, help="Path to the certificate to verify")
    parser.add_argument("--ca-cert", default=DEFAULT_CA_CERT_PATH, help="Path to the CA certificate")
    return parser.parse_args()


def load_certificate(certificate_path: str) -> x509.Certificate:
    """Load an X.509 certificate from PEM data on disk.

    Args:
        certificate_path: Path to the certificate that should be verified.

    Returns:
        The parsed X.509 certificate.

    Raises:
        FileNotFoundError: If the certificate file is missing.
        ValueError: If the certificate cannot be parsed.
    """

    with open(certificate_path, "rb") as certificate_file:
        certificate_data = certificate_file.read()

    return x509.load_pem_x509_certificate(certificate_data)


def verify_signature(certificate: x509.Certificate, ca_certificate: x509.Certificate) -> None:
    """Verify that a certificate was signed by the CA certificate.

    Args:
        certificate: The certificate being checked.
        ca_certificate: The CA certificate whose public key should validate the signature.

    Returns:
        None: The function raises if the signature is invalid.

    Raises:
        InvalidSignature: If signature verification fails.
        TypeError: If the CA public key type is unsupported.
    """

    public_key = ca_certificate.public_key()

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            signature=certificate.signature,
            data=certificate.tbs_certificate_bytes,
            signature_algorithm=ec.ECDSA(certificate.signature_hash_algorithm),
        )
        return

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            signature=certificate.signature,
            data=certificate.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=certificate.signature_hash_algorithm,
        )
        return

    if isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(
            signature=certificate.signature,
            data=certificate.tbs_certificate_bytes,
            algorithm=certificate.signature_hash_algorithm,
        )
        return

    raise TypeError(f"Unsupported CA public key type: {type(public_key).__name__}")


def check_validity(certificate: x509.Certificate) -> bool:
    """Check whether a certificate is valid at the current UTC time.

    Args:
        certificate: The certificate whose validity period should be checked.

    Returns:
        True when the current UTC time falls inside the validity window.
    """

    now = datetime.now(UTC)
    return certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc


def describe_public_key(certificate: x509.Certificate) -> tuple[str, int]:
    """Describe the certificate public key type and size.

    Args:
        certificate: The certificate whose public key metadata should be reported.

    Returns:
        A tuple containing the key type label and key size in bits.
    """

    public_key = certificate.public_key()
    key_type = type(public_key).__name__
    key_size = getattr(public_key, "key_size", 0)
    return key_type, key_size


def print_report(certificate: x509.Certificate, is_valid: bool) -> None:
    """Print a human-readable verification report.

    Args:
        certificate: The certificate being reported on.
        is_valid: Whether the certificate passed verification.

    Returns:
        None: The report is written to standard output.
    """

    key_type, key_size = describe_public_key(certificate)
    signature_algorithm = getattr(certificate.signature_algorithm_oid, "_name", None)
    if not signature_algorithm:
        signature_algorithm = certificate.signature_hash_algorithm.name

    status = "VALID" if is_valid else "INVALID"
    expiry = certificate.not_valid_after_utc.isoformat()
    days_remaining = (certificate.not_valid_after_utc - datetime.now(UTC)).days

    print(f"Status: {status}")
    print(f"Subject: {certificate.subject.rfc4514_string()}")
    print(f"Issuer: {certificate.issuer.rfc4514_string()}")
    print(f"Expiry Date: {expiry}")
    print(f"Days Remaining: {days_remaining}")
    print(f"Key Type: {key_type}")
    print(f"Key Size: {key_size}")
    print(f"Signature Algorithm: {signature_algorithm}")


def verify_certificate(certificate_path: str, ca_certificate_path: str) -> bool:
    """Verify a vehicle certificate against the CA certificate.

    Args:
        certificate_path: Path to the certificate to verify.
        ca_certificate_path: Path to the CA certificate used for verification.

    Returns:
        True when the certificate is valid; otherwise False.

    Raises:
        FileNotFoundError: If either certificate file is missing.
        ValueError: If either certificate file cannot be parsed.
        TypeError: If the CA key type is unsupported.
    """

    LOGGER.info("Loading certificate from %s", certificate_path)
    certificate = load_certificate(certificate_path)
    ca_certificate = load_certificate(ca_certificate_path)

    try:
        verify_signature(certificate, ca_certificate)
        signature_valid = True
    except InvalidSignature:
        signature_valid = False

    validity_valid = check_validity(certificate)
    is_valid = signature_valid and validity_valid
    print_report(certificate, is_valid)
    return is_valid


def main() -> int:
    """Run the certificate verification workflow from the command line.

    Returns:
        Zero if the certificate is valid, otherwise one.
    """

    configure_logging()
    arguments = parse_arguments()
    try:
        is_valid = verify_certificate(arguments.cert, arguments.ca_cert)
        return 0 if is_valid else 1
    except (FileNotFoundError, ValueError, TypeError) as exc:
        LOGGER.exception("Certificate verification failed: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())