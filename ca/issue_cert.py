"""Issue vehicle certificates for the V2V security simulation."""

from __future__ import annotations

import argparse
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
    generate_private_key,
)
from cryptography.x509.oid import NameOID


LOGGER = logging.getLogger(__name__)


# Configure logging so status messages appear in a beginner-friendly format.
def configure_logging() -> None:
    """Configure application logging.

    This sets a simple format like [INFO] message for clear terminal output.

    Returns:
        None
    """
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


# Parse command-line inputs so users can choose vehicle ID and output folder.
def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for certificate issuance.

    Returns:
        argparse.Namespace: Parsed arguments with vehicle_id and output_dir.
    """
    parser = argparse.ArgumentParser(
        description="Issue a vehicle certificate signed by the V2V CA."
    )
    parser.add_argument(
        "--vehicle-id",
        required=True,
        help="Vehicle identifier, for example: vehicle-a",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where vehicle certificate and key are saved, for example: ca/certs",
    )
    return parser.parse_args()


# Load the CA certificate and private key from the ca/certs folder.
def load_ca_materials(ca_dir: Path) -> Tuple[x509.Certificate, EllipticCurvePrivateKey]:
    """Load CA certificate and private key from disk.

    Args:
        ca_dir: Directory containing ca_cert.pem and ca_key.pem.

    Returns:
        Tuple[x509.Certificate, EllipticCurvePrivateKey]:
            The CA certificate and CA private key.
    """
    try:
        # Build exact file paths for the CA artifacts.
        ca_cert_path = ca_dir / "ca_cert.pem"
        ca_key_path = ca_dir / "ca_key.pem"

        # Ensure the CA certificate exists before reading.
        if not ca_cert_path.exists():
            raise FileNotFoundError(
                f"CA certificate not found at {ca_cert_path}. Run ca/ca.py first."
            )

        # Ensure the CA private key exists before reading.
        if not ca_key_path.exists():
            raise FileNotFoundError(
                f"CA private key not found at {ca_key_path}. Run ca/ca.py first."
            )

        # Read and parse the CA certificate from PEM.
        ca_cert_bytes = ca_cert_path.read_bytes()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)

        # Read and parse the CA private key from PEM.
        ca_key_bytes = ca_key_path.read_bytes()
        ca_key_obj = serialization.load_pem_private_key(
            ca_key_bytes,
            password=None,
        )

        # Validate that the loaded key is an elliptic-curve private key.
        if not isinstance(ca_key_obj, EllipticCurvePrivateKey):
            raise TypeError("Loaded CA key is not an EC private key.")

        return ca_cert, ca_key_obj
    except Exception as exc:
        raise RuntimeError(f"Failed to load CA materials: {exc}") from exc


# Generate a fresh ECDSA P-256 key pair for the vehicle.
def generate_vehicle_key() -> EllipticCurvePrivateKey:
    """Generate a new vehicle private key on curve P-256.

    Returns:
        EllipticCurvePrivateKey: Newly generated vehicle private key.
    """
    try:
        return generate_private_key(SECP256R1())
    except Exception as exc:
        raise RuntimeError(f"Failed to generate vehicle key pair: {exc}") from exc


# Build a one-year vehicle certificate and sign it with the CA private key.
def create_vehicle_certificate(
    vehicle_id: str,
    vehicle_public_key: EllipticCurvePublicKey,
    ca_cert: x509.Certificate,
    ca_key: EllipticCurvePrivateKey,
) -> x509.Certificate:
    """Create an X.509 vehicle certificate signed by the CA.

    Args:
        vehicle_id: Vehicle identifier used as the certificate common name.
        vehicle_public_key: Vehicle public key embedded in the certificate.
        ca_cert: CA certificate used as issuer information.
        ca_key: CA private key used to sign the vehicle certificate.

    Returns:
        x509.Certificate: Signed vehicle certificate.
    """
    try:
        # Define who the vehicle is (subject) using CN and O fields.
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, vehicle_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "V2V-Security-Lab"),
            ]
        )

        # Define certificate validity window for one year.
        valid_from = datetime.utcnow()
        try:
            valid_to = valid_from.replace(year=valid_from.year + 1)
        except ValueError:
            valid_to = valid_from + timedelta(days=365)

        # Build certificate fields and allow Digital Signature usage.
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(vehicle_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
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
        )

        # Sign the vehicle certificate with the CA private key.
        return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    except Exception as exc:
        raise RuntimeError(f"Failed to create vehicle certificate: {exc}") from exc


# Save the vehicle certificate and private key in PEM files.
def save_vehicle_artifacts(
    vehicle_id: str,
    vehicle_cert: x509.Certificate,
    vehicle_key: EllipticCurvePrivateKey,
    output_dir: Path,
) -> Tuple[Path, Path]:
    """Save vehicle certificate and private key to disk as PEM files.

    Args:
        vehicle_id: Vehicle identifier used in file names.
        vehicle_cert: Signed certificate for this vehicle.
        vehicle_key: Private key for this vehicle.
        output_dir: Destination directory for output files.

    Returns:
        Tuple[Path, Path]: Paths for certificate file and key file.
    """
    try:
        # Ensure destination folder exists before writing files.
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build output paths based on the vehicle ID.
        cert_path = output_dir / f"{vehicle_id}_cert.pem"
        key_path = output_dir / f"{vehicle_id}_key.pem"

        # Write vehicle certificate in PEM (text-based) format.
        cert_path.write_bytes(vehicle_cert.public_bytes(serialization.Encoding.PEM))

        # Write vehicle private key in PEM format with no encryption for simplicity.
        key_path.write_bytes(
            vehicle_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        return cert_path, key_path
    except Exception as exc:
        raise RuntimeError(f"Failed to save vehicle artifacts: {exc}") from exc


# Format SHA-256 fingerprint bytes as colon-separated hex for human-readable output.
def format_fingerprint(certificate: x509.Certificate) -> str:
    """Generate a readable SHA-256 fingerprint string.

    Args:
        certificate: Certificate whose fingerprint will be computed.

    Returns:
        str: Colon-separated lowercase hexadecimal fingerprint.
    """
    try:
        fp = certificate.fingerprint(hashes.SHA256())
        return ":".join(f"{byte:02x}" for byte in fp)
    except Exception as exc:
        raise RuntimeError(f"Failed to compute certificate fingerprint: {exc}") from exc


# Run the full certificate issuance flow from CLI arguments to saved files.
def issue_vehicle_certificate() -> int:
    """Issue and save a certificate for one vehicle.

    Returns:
        int: 0 on success, 1 on failure.
    """
    try:
        # Read CLI arguments provided by the user.
        args = parse_args()
        vehicle_id = args.vehicle_id.strip()
        output_dir = Path(args.output_dir)

        # Resolve CA directory relative to this script for reliable file loading.
        ca_dir = Path(__file__).resolve().parent / "certs"

        LOGGER.info("Loading CA certificate and key...")
        ca_cert, ca_key = load_ca_materials(ca_dir)

        LOGGER.info("Generating key pair for %s...", vehicle_id)
        vehicle_key = generate_vehicle_key()

        LOGGER.info("Creating certificate for %s...", vehicle_id)
        vehicle_cert = create_vehicle_certificate(
            vehicle_id=vehicle_id,
            vehicle_public_key=vehicle_key.public_key(),
            ca_cert=ca_cert,
            ca_key=ca_key,
        )
        LOGGER.info("Certificate signed by CA.")

        cert_path, key_path = save_vehicle_artifacts(
            vehicle_id=vehicle_id,
            vehicle_cert=vehicle_cert,
            vehicle_key=vehicle_key,
            output_dir=output_dir,
        )

        LOGGER.info("Saved: %s", cert_path.as_posix())
        LOGGER.info("Saved: %s", key_path.as_posix())
        LOGGER.info("Fingerprint (SHA-256): %s", format_fingerprint(vehicle_cert))
        LOGGER.info("Serial: %s", hex(vehicle_cert.serial_number))

        return 0
    except Exception as exc:
        LOGGER.error("Certificate issuance failed: %s", exc)
        return 1


# Start the certificate issuance process when this script is run directly.
if __name__ == "__main__":
    configure_logging()
    raise SystemExit(issue_vehicle_certificate())