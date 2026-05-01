"""Vehicle certificate issuer for the V2V security simulation.

This module loads the CA artifacts, creates a vehicle certificate, and writes
the vehicle certificate and private key to ``ca/certs`` or a chosen output
directory.
"""

from __future__ import annotations

import argparse
import logging
import os
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


LOGGER = logging.getLogger(__name__)
DEFAULT_CA_CERT_PATH = os.path.join("ca", "certs", "ca_cert.pem")
DEFAULT_CA_KEY_PATH = os.path.join("ca", "certs", "ca_key.pem")
DEFAULT_OUTPUT_DIR = os.path.join("ca", "certs")
DEFAULT_CA_PASSPHRASE = "v2v-ca-secret"
V2V_ORGANIZATION = "V2V-Security-Lab"


def configure_logging() -> None:
    """Configure timestamped logging for issuer operations.

    Returns:
        None: This function only configures the Python logging subsystem.
    """

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def parse_arguments() -> argparse.Namespace:
    """Parse the vehicle certificate issuer command-line arguments.

    Returns:
        An argparse namespace containing the requested values.
    """

    parser = argparse.ArgumentParser(description="Issue a V2V vehicle certificate")
    parser.add_argument("--vehicle-id", required=True, help="Vehicle identifier")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for output PEM files")
    parser.add_argument("--ca-cert", default=DEFAULT_CA_CERT_PATH, help="Path to the CA certificate")
    parser.add_argument("--ca-key", default=DEFAULT_CA_KEY_PATH, help="Path to the CA private key")
    parser.add_argument("--ca-passphrase", default=DEFAULT_CA_PASSPHRASE, help="Passphrase protecting the CA private key")
    return parser.parse_args()


def ensure_output_directory(output_directory: str) -> str:
    """Create the vehicle certificate output directory if needed.

    Args:
        output_directory: Directory in which the vehicle certificate files will be written.

    Returns:
        The normalized directory path that now exists on disk.

    Raises:
        OSError: If the directory cannot be created.
    """

    normalized_path = os.path.normpath(output_directory)
    os.makedirs(normalized_path, exist_ok=True)
    return normalized_path


def load_ca_certificate(ca_certificate_path: str) -> x509.Certificate:
    """Load the CA certificate from disk.

    Args:
        ca_certificate_path: Path to the CA certificate in PEM format.

    Returns:
        The parsed CA certificate object.

    Raises:
        FileNotFoundError: If the certificate file is missing.
        ValueError: If the certificate cannot be parsed.
    """

    with open(ca_certificate_path, "rb") as certificate_file:
        certificate_data = certificate_file.read()

    return x509.load_pem_x509_certificate(certificate_data)


def load_ca_private_key(ca_key_path: str, passphrase: str) -> ec.EllipticCurvePrivateKey:
    """Load the encrypted CA private key from disk.

    Args:
        ca_key_path: Path to the encrypted CA private key in PEM format.
        passphrase: Passphrase used to decrypt the private key.

    Returns:
        The decrypted CA private key.

    Raises:
        FileNotFoundError: If the key file is missing.
        ValueError: If the key cannot be loaded or decrypted.
        TypeError: If the passphrase is not valid for the backend loader.
    """

    with open(ca_key_path, "rb") as key_file:
        key_data = key_file.read()

    return serialization.load_pem_private_key(key_data, password=passphrase.encode("utf-8"))


def generate_vehicle_key_pair() -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA P-256 private key for a vehicle.

    Returns:
        A newly generated SECP256R1 private key object.

    Raises:
        ValueError: If key generation fails unexpectedly.
    """

    try:
        return ec.generate_private_key(ec.SECP256R1())
    except ValueError as exc:
        raise ValueError("Unable to generate vehicle private key") from exc


def build_vehicle_certificate(
    vehicle_id: str,
    vehicle_public_key: ec.EllipticCurvePublicKey,
    ca_certificate: x509.Certificate,
    ca_private_key: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    """Build and sign a one-year vehicle certificate with the CA key.

    Args:
        vehicle_id: Unique vehicle identifier used for the certificate subject.
        vehicle_public_key: Public key corresponding to the vehicle private key.
        ca_certificate: CA certificate providing the issuer identity.
        ca_private_key: CA private key used to sign the new certificate.

    Returns:
        A signed X.509 certificate for the vehicle.

    Raises:
        ValueError: If the vehicle identifier is empty.
    """

    if not vehicle_id.strip():
        raise ValueError("vehicle-id cannot be empty")

    now = datetime.now(UTC)
    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, vehicle_id),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, V2V_ORGANIZATION),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(vehicle_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(vehicle_id)]),
            critical=False,
        )
    )

    return builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())


def save_vehicle_artifacts(
    vehicle_id: str,
    certificate: x509.Certificate,
    private_key: ec.EllipticCurvePrivateKey,
    output_directory: str,
) -> tuple[str, str]:
    """Save the vehicle certificate and key to PEM files.

    Args:
        vehicle_id: Vehicle identifier used to build the output filenames.
        certificate: Vehicle certificate to write.
        private_key: Vehicle private key to write in unencrypted PEM format.
        output_directory: Directory that receives the PEM output files.

    Returns:
        A tuple containing the certificate path and private key path.

    Raises:
        OSError: If the files cannot be written.
    """

    certificate_path = os.path.join(output_directory, f"{vehicle_id}_cert.pem")
    key_path = os.path.join(output_directory, f"{vehicle_id}_key.pem")

    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(certificate_path, "wb") as certificate_file:
        certificate_file.write(certificate_bytes)

    with open(key_path, "wb") as key_file:
        key_file.write(key_bytes)

    return certificate_path, key_path


def issue_vehicle_certificate(
    vehicle_id: str,
    output_directory: str,
    ca_certificate_path: str,
    ca_key_path: str,
    ca_passphrase: str,
) -> tuple[str, str]:
    """Create and store a signed vehicle certificate.

    Args:
        vehicle_id: Unique vehicle identifier.
        output_directory: Directory used to save the vehicle certificate files.
        ca_certificate_path: Path to the CA certificate in PEM format.
        ca_key_path: Path to the encrypted CA private key in PEM format.
        ca_passphrase: Passphrase for decrypting the CA private key.

    Returns:
        A tuple containing the certificate path and private key path.

    Raises:
        FileNotFoundError: If any required CA file is missing.
        ValueError: If the CA key cannot be decrypted or the vehicle id is invalid.
        OSError: If the output files cannot be written.
    """

    LOGGER.info("Starting certificate issuance for vehicle %s", vehicle_id)
    output_path = ensure_output_directory(output_directory)
    ca_certificate = load_ca_certificate(ca_certificate_path)
    ca_private_key = load_ca_private_key(ca_key_path, ca_passphrase)
    vehicle_private_key = generate_vehicle_key_pair()

    certificate = build_vehicle_certificate(
        vehicle_id=vehicle_id,
        vehicle_public_key=vehicle_private_key.public_key(),
        ca_certificate=ca_certificate,
        ca_private_key=ca_private_key,
    )

    certificate_path, key_path = save_vehicle_artifacts(
        vehicle_id=vehicle_id,
        certificate=certificate,
        private_key=vehicle_private_key,
        output_directory=output_path,
    )

    fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
    print(f"Certificate issued for {vehicle_id}")
    print(f"Fingerprint (SHA-256): {fingerprint}")
    print(f"Serial Number: {certificate.serial_number}")
    LOGGER.info("Saved vehicle certificate to %s", certificate_path)
    LOGGER.info("Saved vehicle private key to %s", key_path)
    return certificate_path, key_path


def main() -> int:
    """Run the vehicle certificate issuer from the command line.

    Returns:
        Zero on success, or a non-zero exit code when an error occurs.
    """

    configure_logging()
    arguments = parse_arguments()
    try:
        issue_vehicle_certificate(
            vehicle_id=arguments.vehicle_id,
            output_directory=arguments.output_dir,
            ca_certificate_path=arguments.ca_cert,
            ca_key_path=arguments.ca_key,
            ca_passphrase=arguments.ca_passphrase,
        )
        return 0
    except (FileNotFoundError, ValueError, OSError, InvalidSignature) as exc:
        LOGGER.exception("Vehicle certificate issuance failed: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())