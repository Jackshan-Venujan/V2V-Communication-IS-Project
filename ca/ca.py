"""Certificate Authority bootstrap for the V2V security simulation.

This module creates a self-signed ECDSA P-256 root certificate and an
encrypted private key, then stores both artifacts in ``ca/certs``.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


LOGGER = logging.getLogger(__name__)
CA_PASSPHRASE = b"v2v-ca-secret"
CA_COMMON_NAME = "V2V-Root-CA"
CA_ORGANIZATION = "V2V-Security-Lab"


def configure_logging() -> None:
	"""Configure timestamped logging for CA operations.

	Returns:
		None: This function only configures the Python logging subsystem.
	"""

	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
	)


def ensure_certificate_directory(directory_path: str) -> str:
	"""Create the certificate output directory if it does not already exist.

	Args:
		directory_path: Directory path where CA artifacts should be written.

	Returns:
		The normalized directory path that now exists on disk.

	Raises:
		OSError: If the directory cannot be created.
	"""

	normalized_path = os.path.normpath(directory_path)
	os.makedirs(normalized_path, exist_ok=True)
	return normalized_path


def generate_ca_key_pair() -> ec.EllipticCurvePrivateKey:
	"""Generate an ECDSA P-256 private key for the certificate authority.

	Returns:
		A newly generated SECP256R1 private key object.

	Raises:
		ValueError: If key generation fails unexpectedly.
	"""

	try:
		return ec.generate_private_key(ec.SECP256R1())
	except ValueError as exc:
		raise ValueError("Unable to generate CA private key") from exc


def build_root_certificate(
	private_key: ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
	"""Build a self-signed X.509 root certificate for the CA.

	Args:
		private_key: The private key used both to sign the certificate and to
			supply the matching public key.

	Returns:
		A self-signed X.509 certificate configured as a root CA.

	Raises:
		InvalidKey: If the provided key is not suitable for certificate use.
	"""

	if private_key is None:
		raise InvalidKey("A private key is required to build the CA certificate")

	now = datetime.now(UTC)
	subject = issuer = x509.Name(
		[
			x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, CA_COMMON_NAME),
			x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
		]
	)

	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(private_key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now - timedelta(minutes=1))
		.not_valid_after(now + timedelta(days=3650))
		.add_extension(
			x509.BasicConstraints(ca=True, path_length=1),
			critical=True,
		)
		.add_extension(
			x509.KeyUsage(
				digital_signature=False,
				content_commitment=False,
				key_encipherment=False,
				data_encipherment=False,
				key_agreement=False,
				key_cert_sign=True,
				crl_sign=True,
				encipher_only=False,
				decipher_only=False,
			),
			critical=True,
		)
	)

	return builder.sign(private_key=private_key, algorithm=hashes.SHA256())


def save_ca_artifacts(
	certificate: x509.Certificate,
	private_key: ec.EllipticCurvePrivateKey,
	output_directory: str,
) -> tuple[str, str]:
	"""Persist the CA certificate and encrypted private key to disk.

	Args:
		certificate: The certificate to write in PEM format.
		private_key: The matching CA private key.
		output_directory: Directory where the PEM files should be saved.

	Returns:
		A tuple containing the certificate path and private key path.

	Raises:
		OSError: If the files cannot be written.
	"""

	certificate_path = os.path.join(output_directory, "ca_cert.pem")
	key_path = os.path.join(output_directory, "ca_key.pem")

	certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)
	key_bytes = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.BestAvailableEncryption(CA_PASSPHRASE),
	)

	with open(certificate_path, "wb") as certificate_file:
		certificate_file.write(certificate_bytes)

	with open(key_path, "wb") as key_file:
		key_file.write(key_bytes)

	return certificate_path, key_path


def print_certificate_details(certificate: x509.Certificate) -> None:
	"""Print a readable summary of the generated CA certificate.

	Args:
		certificate: The certificate whose metadata should be displayed.

	Returns:
		None: The details are printed to standard output.
	"""

	key_type = type(certificate.public_key()).__name__
	signature_algorithm = getattr(certificate.signature_algorithm_oid, "_name", None)
	if not signature_algorithm:
		signature_algorithm = certificate.signature_hash_algorithm.name

	print("CA certificate created successfully")
	print(f"Subject: {certificate.subject.rfc4514_string()}")
	print(f"Issuer: {certificate.issuer.rfc4514_string()}")
	print(f"Serial: {certificate.serial_number}")
	print(f"Valid From: {certificate.not_valid_before_utc.isoformat()}")
	print(f"Valid To: {certificate.not_valid_after_utc.isoformat()}")
	print(f"Key Type: {key_type}")
	print(f"Signature Algorithm: {signature_algorithm}")


def create_certificate_authority() -> tuple[str, str]:
	"""Create, sign, and store the CA certificate and private key.

	Returns:
		A tuple containing the certificate path and private key path.

	Raises:
		OSError: If the output directory or files cannot be created.
		ValueError: If key generation fails.
		InvalidKey: If the key cannot be used to build the certificate.
	"""

	LOGGER.info("Starting CA creation workflow")
	output_directory = ensure_certificate_directory(os.path.join("ca", "certs"))
	LOGGER.info("Using output directory: %s", output_directory)

	private_key = generate_ca_key_pair()
	LOGGER.info("Generated ECDSA P-256 CA key pair")

	certificate = build_root_certificate(private_key)
	LOGGER.info("Built self-signed root certificate")

	certificate_path, key_path = save_ca_artifacts(certificate, private_key, output_directory)
	LOGGER.info("Saved CA certificate to %s", certificate_path)
	LOGGER.info("Saved encrypted CA private key to %s", key_path)

	print_certificate_details(certificate)
	return certificate_path, key_path


def main() -> int:
	"""Run the CA bootstrap workflow from the command line.

	Returns:
		Zero on success, or a non-zero exit code when an error occurs.
	"""

	configure_logging()
	try:
		create_certificate_authority()
		return 0
	except (OSError, ValueError, InvalidKey) as exc:
		LOGGER.exception("CA creation failed: %s", exc)
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
