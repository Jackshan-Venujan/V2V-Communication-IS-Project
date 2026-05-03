"""Certificate Authority setup for the V2V security simulation."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    SECP256R1,
    generate_private_key,
)
from cryptography.x509.oid import NameOID


LOGGER = logging.getLogger(__name__)


# Configure logging so every message has a timestamp, log level, and message.
def configure_logging() -> None:
    """Set up application logging.

    This function configures the logging system so the CA prints readable status
    messages with timestamps.

    Returns:
        None
    """

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# Generate a cryptographically random key pair using the P-256 elliptic curve.
def generate_ca_key() -> EllipticCurvePrivateKey:
    """Generate the CA private key.

    This function creates an ECDSA key pair on the NIST P-256 curve. The
    returned private key also contains the public key.

    Returns:
        EllipticCurvePrivateKey: The generated CA private key.
    """

    try:
        return generate_private_key(SECP256R1())
    except Exception as exc:
        raise RuntimeError(f"Failed to generate CA key pair: {exc}") from exc


# Build the CA subject name and the self-signed root certificate.
def create_self_signed_certificate(
    private_key: EllipticCurvePrivateKey,
) -> x509.Certificate:
    """Create a self-signed X.509 certificate for the CA.

    Args:
        private_key: The CA private key used to sign the certificate.

    Returns:
        x509.Certificate: The generated self-signed CA certificate.
    """

    try:
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "V2V-Root-CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V2V-Security-Lab"),
            ]
        )

        # Set the certificate validity period to 10 years from today.
        valid_from = datetime.utcnow()
        try:
            valid_to = valid_from.replace(year=valid_from.year + 10)
        except ValueError:
            valid_to = valid_from + timedelta(days=3650)

        # Mark the certificate as a Certificate Authority and allow certificate signing.
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )

        return builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    except Exception as exc:
        raise RuntimeError(f"Failed to create self-signed CA certificate: {exc}") from exc


# Save the CA certificate and key as PEM files inside the certs folder.
def save_ca_artifacts(
    certificate: x509.Certificate,
    private_key: EllipticCurvePrivateKey,
    output_directory: Path,
) -> tuple[Path, Path]:
    """Save the CA certificate and private key to disk.

    PEM means Privacy Enhanced Mail, a text-based format commonly used for
    storing certificates and keys.

    Args:
        certificate: The CA certificate to save.
        private_key: The CA private key to save.
        output_directory: Folder where the PEM files will be written.

    Returns:
        tuple[Path, Path]: Paths to the saved certificate and key files.
    """

    try:
        output_directory.mkdir(parents=True, exist_ok=True)

        # Write the public certificate in PEM format so it can be shared safely.
        cert_path = output_directory / "ca_cert.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

        # Write the private key in PEM format and keep this file secret.
        key_path = output_directory / "ca_key.pem"
        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        return cert_path, key_path
    except Exception as exc:
        raise RuntimeError(f"Failed to save CA artifacts: {exc}") from exc


# Log a human-readable summary of the new CA certificate.
def log_certificate_summary(certificate: x509.Certificate) -> None:
    """Log a readable summary of the CA certificate.

    Args:
        certificate: The CA certificate whose fields will be displayed.

    Returns:
        None
    """

    try:
        subject = certificate.subject.rfc4514_string()
        issuer = certificate.issuer.rfc4514_string()
        serial_number = hex(certificate.serial_number)
        valid_from = certificate.not_valid_before.strftime("%Y-%m-%d")
        valid_to = certificate.not_valid_after.strftime("%Y-%m-%d")

        LOGGER.info(
            "Certificate details:\n"
            f"  Subject  : {subject}\n"
            f"  Issuer   : {issuer} (self-signed)\n"
            f"  Serial   : {serial_number}\n"
            f"  Valid From: {valid_from}\n"
            f"  Valid To  : {valid_to}\n"
            f"  Key Type : ECDSA P-256"
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to log certificate summary: {exc}") from exc


# Run the full CA setup workflow from start to finish.
def setup_ca() -> int:
    """Create the CA key pair, certificate, and output files.

    This function drives the full CA setup flow and returns an exit code that
    the command-line entry point can pass to the operating system.

    Returns:
        int: Zero on success, non-zero on failure.
    """

    try:
        LOGGER.info("Generating CA key pair (ECDSA P-256)...")
        private_key = generate_ca_key()
        LOGGER.info("CA key pair generated.")

        LOGGER.info("Creating self-signed root certificate...")
        certificate = create_self_signed_certificate(private_key)

        log_certificate_summary(certificate)

        # Save the certificate and key into the ca/certs folder next to this file.
        cert_path, key_path = save_ca_artifacts(
            certificate=certificate,
            private_key=private_key,
            output_directory=Path(__file__).resolve().parent / "certs",
        )

        LOGGER.info("Saved: %s", cert_path.as_posix())
        LOGGER.info("Saved: %s", key_path.as_posix())
        LOGGER.info("CA initialised successfully. Share ca_cert.pem with all vehicles.")
        return 0
    except Exception as exc:
        LOGGER.exception("CA setup failed: %s", exc)
        return 1


if __name__ == "__main__":
    # Start the CA setup when the file is executed directly.
    configure_logging()
    raise SystemExit(setup_ca())