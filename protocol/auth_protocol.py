"""Authentication protocol for the V2V security simulation.

Implements the 4-step mutual authentication handshake between vehicles:

    Vehicle A (Initiator)              Vehicle B (Responder)
        |--- HELLO {CertA, NonceA, TS} ---------->|
        |                           Verify CertA against CA
        |<-- CHALLENGE {CertB, NonceB, Sign(NA+NB)} --|
        |  Verify CertB, verify signature              |
        |--- RESPONSE {Sign(NA+NB), ECDH_PubA} -->|
        |                           Verify sig, compute shared secret
        |<-- ACK {ECDH_PubB, SessionEstablished} --|
        |  Compute same shared secret -> Session Key   |

After a successful handshake both vehicles share an identical 32-byte
AES-256 session key derived via ECDHE + HKDF-SHA256.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so cross-package imports work
# regardless of which directory the user runs the script from.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from crypto.crypto import (  # noqa: E402
    derive_session_key,
    ecdh_shared_secret,
    ecdsa_sign,
    ecdsa_verify,
    generate_ecdh_keypair,
    load_public_key,
    serialize_public_key,
)

LOGGER = logging.getLogger(__name__)


# ── Custom Exceptions ─────────────────────────────────────────────────────


class AuthError(Exception):
    """Base exception for authentication errors."""


class ReplayError(AuthError):
    """Raised when a replayed nonce is detected."""


class StaleMessageError(AuthError):
    """Raised when a message timestamp is too old."""


class CertificateError(AuthError):
    """Raised when certificate verification fails."""


# ── Message Dataclasses ───────────────────────────────────────────────────


@dataclass
class HelloMessage:
    """Step 1 of the handshake — initiator announces itself.

    Fields:
        vehicle_id: Human-readable vehicle identifier.
        certificate_pem: Vehicle's X.509 certificate in PEM text.
        nonce: Random 32-byte value as a hex string (64 hex chars).
        timestamp: Unix timestamp when the message was created.
        msg_type: Constant type tag for deserialisation routing.
    """

    vehicle_id: str
    certificate_pem: str
    nonce: str
    timestamp: float
    msg_type: str = "HELLO"

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> HelloMessage:
        return cls(**json.loads(data))


@dataclass
class ChallengeMessage:
    """Step 2 — responder proves identity and challenges the initiator."""

    vehicle_id: str
    certificate_pem: str
    nonce: str
    signed_nonces: str  # ECDSA sig of (initiator_nonce + responder_nonce) as hex
    timestamp: float
    msg_type: str = "CHALLENGE"

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> ChallengeMessage:
        return cls(**json.loads(data))


@dataclass
class ResponseMessage:
    """Step 3 — initiator proves identity and starts key exchange."""

    signed_nonces: str
    ecdh_public_key_pem: str  # Ephemeral ECDH public key for forward secrecy
    timestamp: float
    msg_type: str = "RESPONSE"

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> ResponseMessage:
        return cls(**json.loads(data))


@dataclass
class AckMessage:
    """Step 4 — responder completes key exchange."""

    ecdh_public_key_pem: str
    session_established: bool = True
    msg_type: str = "ACK"

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> AckMessage:
        return cls(**json.loads(data))


# ── Replay Protection ─────────────────────────────────────────────────────


class ReplayCache:
    """Stores recently seen nonces to detect replay attacks.

    When a message arrives we check if its nonce is already in the cache.
    If yes → REPLAY ATTACK — reject.  If no → add nonce and proceed.
    Nonces expire after *window_seconds* (default 300 s = 5 min).
    """

    def __init__(self, window_seconds: int = 300) -> None:
        self._window = window_seconds
        self._seen: dict[str, float] = {}  # {nonce_hex: expiry_timestamp}

    def check_and_add(self, nonce: str) -> None:
        """Reject duplicate nonces; store new ones.

        Raises:
            ReplayError: If the nonce has already been seen.
        """
        self._cleanup()
        if nonce in self._seen:
            raise ReplayError(f"Nonce already seen: {nonce[:16]}...")
        self._seen[nonce] = time.time() + self._window

    def _cleanup(self) -> None:
        """Remove expired nonces from the cache."""
        now = time.time()
        expired = [n for n, exp in self._seen.items() if exp < now]
        for n in expired:
            del self._seen[n]


class TimestampValidator:
    """Rejects messages whose timestamp is outside the acceptable window.

    A message from 10 seconds ago could be a replay — reject it.
    """

    def __init__(self, max_age_seconds: float = 5.0) -> None:
        self._max_age = max_age_seconds

    def validate(self, timestamp: float) -> None:
        """Raise if the timestamp is too far from *now*.

        Raises:
            StaleMessageError: If the message is older than max_age_seconds.
        """
        age = abs(time.time() - timestamp)
        if age > self._max_age:
            raise StaleMessageError(
                f"Message is {age:.1f}s old (max {self._max_age}s)"
            )


# ── Certificate Verification Helper ──────────────────────────────────────


def verify_certificate_against_ca(
    cert_pem: str | bytes,
    ca_cert_pem: bytes,
) -> ec.EllipticCurvePublicKey:
    """Verify a vehicle certificate was signed by our trusted CA.

    Steps performed:
      1. Parse the vehicle certificate and the CA certificate from PEM.
      2. Verify the CA's ECDSA-SHA256 signature on the vehicle certificate.
      3. Check the certificate is within its validity dates.
      4. Return the vehicle's public key.

    Args:
        cert_pem: Vehicle certificate in PEM format (str or bytes).
        ca_cert_pem: CA certificate in PEM format (bytes).

    Returns:
        The vehicle's ECDSA public key extracted from its certificate.

    Raises:
        CertificateError: On any verification failure.
    """
    try:
        cert_bytes = (
            cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem
        )
        cert = x509.load_pem_x509_certificate(cert_bytes)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

        # Verify the CA's signature on the vehicle certificate.
        # If the certificate was forged this will raise InvalidSignature.
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()),
        )

        # Check validity dates (handle both tz-aware and naive datetimes).
        now = datetime.now(timezone.utc)
        nb = getattr(cert, "not_valid_before_utc", None)
        if nb is None:
            nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = getattr(cert, "not_valid_after_utc", None)
        if na is None:
            na = cert.not_valid_after.replace(tzinfo=timezone.utc)

        if now < nb:
            raise CertificateError("Certificate is not yet valid")
        if now > na:
            raise CertificateError("Certificate has expired")

        pub_key = cert.public_key()
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            raise CertificateError("Certificate does not contain an EC public key")

        return pub_key

    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError(f"Certificate verification failed: {exc}") from exc


# ── Main Authentication Protocol ─────────────────────────────────────────


class AuthProtocol:
    """Implements the 4-step V2V mutual authentication handshake.

    Both vehicles instantiate this class.  One runs the *initiator* path
    (build_hello → process_challenge → process_ack) and the other runs
    the *responder* path (process_hello → process_response).

    After a successful handshake ``self.session_key`` contains the shared
    32-byte AES-256 key for encrypting BSMs.
    """

    def __init__(
        self,
        vehicle_id: str,
        private_key: ec.EllipticCurvePrivateKey,
        certificate_pem: bytes,
        ca_cert_pem: bytes,
    ) -> None:
        self.vehicle_id = vehicle_id
        self.private_key = private_key
        self.certificate_pem = certificate_pem
        self.ca_cert_pem = ca_cert_pem

        self.replay_cache = ReplayCache()
        self.timestamp_validator = TimestampValidator(max_age_seconds=5.0)

        # Handshake state — populated during the exchange
        self.my_nonce: str = ""
        self.peer_nonce: str = ""
        self.peer_public_key: ec.EllipticCurvePublicKey | None = None
        self.session_key: bytes | None = None
        self._ecdh_private: ec.EllipticCurvePrivateKey | None = None
        self._ecdh_public: ec.EllipticCurvePublicKey | None = None

    # ── Step 1 (Initiator) ────────────────────────────────────────

    def build_hello(self) -> HelloMessage:
        """Build a HELLO message to start the handshake."""
        self.my_nonce = os.urandom(32).hex()
        hello = HelloMessage(
            vehicle_id=self.vehicle_id,
            certificate_pem=self.certificate_pem.decode("utf-8"),
            nonce=self.my_nonce,
            timestamp=time.time(),
        )
        LOGGER.info("[%s] Sent HELLO (nonce=%s…)", self.vehicle_id, self.my_nonce[:8])
        return hello

    # ── Step 2 (Responder) ────────────────────────────────────────

    def process_hello(self, msg: HelloMessage) -> ChallengeMessage:
        """Verify the HELLO and return a CHALLENGE.

        Checks: timestamp freshness, nonce replay, certificate validity.
        Signs both nonces to prove we hold our private key.
        """
        LOGGER.info("[%s] Received HELLO from %s", self.vehicle_id, msg.vehicle_id)

        # 1. Reject stale messages — could be replayed from hours ago
        self.timestamp_validator.validate(msg.timestamp)

        # 2. Reject replayed nonces — attacker recording and replaying HELLO
        self.replay_cache.check_and_add(msg.nonce)

        # 3. Verify peer certificate was signed by our trusted CA
        self.peer_public_key = verify_certificate_against_ca(
            msg.certificate_pem, self.ca_cert_pem
        )
        LOGGER.info("[%s] Certificate VALID for %s", self.vehicle_id, msg.vehicle_id)

        # 4. Store peer nonce; generate our own
        self.peer_nonce = msg.nonce
        self.my_nonce = os.urandom(32).hex()

        # 5. Sign (peer_nonce + our_nonce) — proves private key possession
        nonce_data = bytes.fromhex(self.peer_nonce) + bytes.fromhex(self.my_nonce)
        signature = ecdsa_sign(self.private_key, nonce_data)

        challenge = ChallengeMessage(
            vehicle_id=self.vehicle_id,
            certificate_pem=self.certificate_pem.decode("utf-8"),
            nonce=self.my_nonce,
            signed_nonces=signature.hex(),
            timestamp=time.time(),
        )
        LOGGER.info("[%s] Sent CHALLENGE (nonce=%s…)", self.vehicle_id, self.my_nonce[:8])
        return challenge

    # ── Step 3 (Initiator) ────────────────────────────────────────

    def process_challenge(self, msg: ChallengeMessage) -> ResponseMessage:
        """Verify the CHALLENGE and return a RESPONSE with our ECDH key."""
        LOGGER.info("[%s] Received CHALLENGE from %s", self.vehicle_id, msg.vehicle_id)

        self.timestamp_validator.validate(msg.timestamp)
        self.replay_cache.check_and_add(msg.nonce)

        # Verify peer cert
        self.peer_public_key = verify_certificate_against_ca(
            msg.certificate_pem, self.ca_cert_pem
        )
        LOGGER.info("[%s] Certificate VALID for %s", self.vehicle_id, msg.vehicle_id)

        # Verify peer's signature on (our_nonce + their_nonce)
        self.peer_nonce = msg.nonce
        expected_data = bytes.fromhex(self.my_nonce) + bytes.fromhex(self.peer_nonce)
        if not ecdsa_verify(
            self.peer_public_key, expected_data, bytes.fromhex(msg.signed_nonces)
        ):
            raise AuthError("Challenge signature invalid — possible impersonation")
        LOGGER.info("[%s] Challenge signature verified ✓", self.vehicle_id)

        # Generate ephemeral ECDH key pair (forward secrecy)
        self._ecdh_private, self._ecdh_public = generate_ecdh_keypair()

        # Sign nonces with OUR private key
        our_sig = ecdsa_sign(self.private_key, expected_data)

        response = ResponseMessage(
            signed_nonces=our_sig.hex(),
            ecdh_public_key_pem=serialize_public_key(self._ecdh_public).decode("utf-8"),
            timestamp=time.time(),
        )
        LOGGER.info("[%s] Sent RESPONSE with ECDH public key", self.vehicle_id)
        return response

    # ── Step 4a (Responder) ───────────────────────────────────────

    def process_response(
        self, msg: ResponseMessage, original_hello: HelloMessage
    ) -> AckMessage:
        """Verify the RESPONSE, derive the session key, and return an ACK."""
        LOGGER.info("[%s] Received RESPONSE", self.vehicle_id)

        self.timestamp_validator.validate(msg.timestamp)

        # Verify initiator's signature on (their_nonce + our_nonce)
        nonce_data = bytes.fromhex(self.peer_nonce) + bytes.fromhex(self.my_nonce)
        if not ecdsa_verify(
            self.peer_public_key, nonce_data, bytes.fromhex(msg.signed_nonces)
        ):
            raise AuthError("Response signature invalid")
        LOGGER.info("[%s] Response signature verified ✓", self.vehicle_id)

        # Generate our ECDH key pair and compute shared secret
        self._ecdh_private, self._ecdh_public = generate_ecdh_keypair()
        peer_ecdh_pub = load_public_key(msg.ecdh_public_key_pem.encode("utf-8"))
        shared_secret = ecdh_shared_secret(self._ecdh_private, peer_ecdh_pub)

        # Derive session key — initiator nonce first for consistency
        nonce_a = bytes.fromhex(self.peer_nonce)  # initiator's nonce
        nonce_b = bytes.fromhex(self.my_nonce)    # our nonce (responder)
        self.session_key = derive_session_key(shared_secret, nonce_a, nonce_b)

        LOGGER.info("[%s] Session key derived (forward secrecy: ENABLED)", self.vehicle_id)

        ack = AckMessage(
            ecdh_public_key_pem=serialize_public_key(self._ecdh_public).decode("utf-8"),
        )
        LOGGER.info("[%s] Sent ACK — handshake complete (responder)", self.vehicle_id)
        return ack

    # ── Step 4b (Initiator) ───────────────────────────────────────

    def process_ack(self, msg: AckMessage) -> bytes:
        """Process the ACK, derive the session key, and return it.

        Both vehicles compute the same shared secret via ECDH mathematics:
        ``A_priv * B_pub == B_priv * A_pub``  →  identical session keys.
        """
        LOGGER.info("[%s] Received ACK — session established", self.vehicle_id)

        peer_ecdh_pub = load_public_key(msg.ecdh_public_key_pem.encode("utf-8"))
        shared_secret = ecdh_shared_secret(self._ecdh_private, peer_ecdh_pub)

        # Same nonce order as the responder used
        nonce_a = bytes.fromhex(self.my_nonce)    # initiator's nonce (us)
        nonce_b = bytes.fromhex(self.peer_nonce)  # responder's nonce
        self.session_key = derive_session_key(shared_secret, nonce_a, nonce_b)

        LOGGER.info(
            "[%s] MUTUAL AUTHENTICATION COMPLETE — session key derived", self.vehicle_id
        )
        return self.session_key


# ── Demo ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    certs_dir = Path(__file__).resolve().parent.parent / "ca" / "certs"

    try:
        ca_pem = (certs_dir / "ca_cert.pem").read_bytes()
        a_cert = (certs_dir / "vehicle-a_cert.pem").read_bytes()
        a_key_pem = (certs_dir / "vehicle-a_key.pem").read_bytes()
        b_cert = (certs_dir / "vehicle-b_cert.pem").read_bytes()
        b_key_pem = (certs_dir / "vehicle-b_key.pem").read_bytes()
    except FileNotFoundError as e:
        print(f"ERROR: {e}\nRun 'python ca/ca.py' and issue certs first.")
        sys.exit(1)

    from crypto.crypto import load_private_key

    a_key = load_private_key(a_key_pem)
    b_key = load_private_key(b_key_pem)

    auth_a = AuthProtocol("vehicle-a", a_key, a_cert, ca_pem)
    auth_b = AuthProtocol("vehicle-b", b_key, b_cert, ca_pem)

    print("\n=== V2V AUTHENTICATION HANDSHAKE DEMO ===\n")
    start = time.perf_counter()

    # Step 1 — Vehicle A sends HELLO
    hello = auth_a.build_hello()

    # Step 2 — Vehicle B processes HELLO, sends CHALLENGE
    challenge = auth_b.process_hello(hello)

    # Step 3 — Vehicle A processes CHALLENGE, sends RESPONSE
    response = auth_a.process_challenge(challenge)

    # Step 4a — Vehicle B processes RESPONSE, sends ACK
    ack = auth_b.process_response(response, hello)

    # Step 4b — Vehicle A processes ACK
    key_a = auth_a.process_ack(ack)

    elapsed = (time.perf_counter() - start) * 1000

    key_b = auth_b.session_key
    print(f"\nVehicle A session key: {key_a.hex()[:32]}…")
    print(f"Vehicle B session key: {key_b.hex()[:32]}…")
    print(f"Keys match: {key_a == key_b}")
    print(f"Handshake time: {elapsed:.1f} ms")
    print("\n[OK] Mutual authentication successful - both vehicles share the same key!")
