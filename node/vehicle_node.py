"""Main vehicle node — TCP networking, authentication, and BSM exchange.

Each vehicle runs one instance of this script.  One vehicle is the
*server* (listens on a port) and the other is the *client* (connects).
After a successful 4-step handshake they exchange encrypted BSMs every
second.

Usage
-----
    # Terminal 1 — Vehicle A (server)
    python node/vehicle_node.py --vehicle-id vehicle-a --port 9001 ^
        --cert ca/certs/vehicle-a_cert.pem --key ca/certs/vehicle-a_key.pem ^
        --ca-cert ca/certs/ca_cert.pem --dashboard-port 5001

    # Terminal 2 — Vehicle B (client connects to A)
    python node/vehicle_node.py --vehicle-id vehicle-b --port 9002 ^
        --cert ca/certs/vehicle-b_cert.pem --key ca/certs/vehicle-b_key.pem ^
        --ca-cert ca/certs/ca_cert.pem --dashboard-port 5002 ^
        --peer-host 127.0.0.1 --peer-port 9001
"""

from __future__ import annotations

import argparse
import logging
import random
import socket
import struct
import sys
import threading
import time
from pathlib import Path

# Ensure project root is on sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from crypto.crypto import load_private_key  # noqa: E402
from protocol.auth_protocol import (  # noqa: E402
    AckMessage,
    AuthError,
    AuthProtocol,
    ChallengeMessage,
    HelloMessage,
    ReplayCache,
    ResponseMessage,
    TimestampValidator,
)
from protocol.v2v_protocol import (  # noqa: E402
    BasicSafetyMessage,
    MessageLogger,
    ReplayError,
    SequenceError,
    TamperError,
    secure_receive,
    secure_send,
)

log = logging.getLogger(__name__)


# ── Rate Limiter (Availability — DoS Protection) ─────────────────────────
# Tracks incoming message rates per sender and drops excess traffic to
# prevent a single malicious node from overwhelming the system.


class RateLimiter:
    """Limit incoming messages per sender to prevent DoS flooding.

    If a sender exceeds *max_per_second* messages within a 1-second
    sliding window, subsequent messages are silently dropped until the
    window expires.  This keeps the node available for legitimate peers.
    """

    def __init__(self, max_per_second: int = 15) -> None:
        self._max = max_per_second
        self._counts: dict[str, list[float]] = {}  # {sender_id: [timestamps]}
        self._lock = threading.Lock()
        self.total_dropped: int = 0

    def allow(self, sender_id: str) -> bool:
        """Return True if the sender is within rate limits, False to drop."""
        now = time.time()
        with self._lock:
            timestamps = self._counts.get(sender_id, [])
            # Keep only timestamps within the last 1 second
            timestamps = [t for t in timestamps if now - t < 1.0]
            if len(timestamps) >= self._max:
                self.total_dropped += 1
                log.warning(
                    "[RATE-LIMIT] Dropping message from %s "
                    "(%d msgs/sec exceeds limit of %d)",
                    sender_id, len(timestamps), self._max,
                )
                self._counts[sender_id] = timestamps
                return False
            timestamps.append(now)
            self._counts[sender_id] = timestamps
            return True



# ── TCP Framing Helpers ───────────────────────────────────────────────────
# TCP is a byte stream — it has no concept of "messages".  We prefix every
# message with a 4-byte big-endian length so the receiver knows exactly
# how many bytes to read.


def send_framed(sock: socket.socket, data: bytes) -> None:
    """Send *data* prefixed with a 4-byte length header."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Block until exactly *n* bytes have been received."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf += chunk
    return buf


def recv_framed(sock: socket.socket) -> bytes:
    """Receive a length-prefixed message."""
    header = _recv_exactly(sock, 4)
    length = struct.unpack(">I", header)[0]
    return _recv_exactly(sock, length)


# ── Vehicle Node ──────────────────────────────────────────────────────────


class VehicleNode:
    """Represents a single vehicle in the V2V simulation."""

    def __init__(
        self,
        vehicle_id: str,
        port: int,
        cert_path: str,
        key_path: str,
        ca_cert_path: str,
        bsm_interval: float = 1.0,
        dashboard_port: int = 5000,
    ) -> None:
        self.vehicle_id = vehicle_id
        self.port = port
        self.bsm_interval = bsm_interval
        self.dashboard_port = dashboard_port

        # Load cryptographic material
        self.cert_pem = Path(cert_path).read_bytes()
        self.private_key = load_private_key(Path(key_path).read_bytes())
        self.ca_cert_pem = Path(ca_cert_path).read_bytes()

        # Build the AuthProtocol instance
        self.auth = AuthProtocol(
            vehicle_id, self.private_key, self.cert_pem, self.ca_cert_pem
        )

        # Message subsystem
        self.logger = MessageLogger()
        self.replay_cache = ReplayCache()
        self.timestamp_validator = TimestampValidator(max_age_seconds=5.0)

        # Session state — set after a successful handshake
        self.session_key: bytes | None = None
        self.peer_public_key = None
        self.peer_id: str | None = None

        # Rate limiter — availability protection against DoS flooding
        self.rate_limiter = RateLimiter(max_per_second=15)

        # Networking
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = True
        self._seq = 0
        self._last_peer_seq: int | None = None

        # Auto-reconnection state — availability protection against drops
        self._peer_host: str | None = None
        self._peer_port: int | None = None
        self._is_initiator: bool = False
        self._conn: socket.socket | None = None
        self._conn_lock = threading.Lock()

    # ── Server ────────────────────────────────────────────────────

    def start_server(self) -> None:
        """Bind and listen on ``self.port``."""
        self.server_sock.bind(("0.0.0.0", self.port))
        self.server_sock.listen(1)
        log.info("[%s] Listening on port %d ...", self.vehicle_id, self.port)
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()

    def _accept_loop(self) -> None:
        """Accept ONE incoming connection and run the responder handshake."""
        try:
            conn, addr = self.server_sock.accept()
            log.info("[%s] Peer connected from %s", self.vehicle_id, addr)
            self._run_handshake_responder(conn)
        except OSError:
            pass  # socket closed during shutdown

    # ── Client ────────────────────────────────────────────────────

    def connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to a peer and run the initiator handshake."""
        # Store peer info so auto-reconnection can find them again
        self._peer_host = host
        self._peer_port = port
        self._is_initiator = True

        retries = 5
        for attempt in range(1, retries + 1):
            try:
                log.info(
                    "[%s] Connecting to %s:%d (attempt %d/%d)...",
                    self.vehicle_id, host, port, attempt, retries,
                )
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.settimeout(10)
                conn.connect((host, port))
                conn.settimeout(None)
                self._run_handshake_initiator(conn)
                return True
            except (ConnectionRefusedError, OSError) as exc:
                log.warning("[%s] Attempt %d failed: %s", self.vehicle_id, attempt, exc)
                if attempt < retries:
                    time.sleep(2 * attempt)  # exponential backoff
        log.error("[%s] Could not connect after %d attempts", self.vehicle_id, retries)
        return False

    # ── Handshake (Initiator) ─────────────────────────────────────

    def _run_handshake_initiator(self, conn: socket.socket) -> None:
        """Execute the 4-step handshake as INITIATOR."""
        try:
            # Step 1 — send HELLO
            hello = self.auth.build_hello()
            send_framed(conn, hello.to_json().encode())

            # Step 2 — receive CHALLENGE
            data = recv_framed(conn)
            challenge = ChallengeMessage.from_json(data.decode())

            # Step 3 — process CHALLENGE, send RESPONSE
            response = self.auth.process_challenge(challenge)
            send_framed(conn, response.to_json().encode())
            self.peer_id = challenge.vehicle_id

            # Step 4 — receive ACK
            data = recv_framed(conn)
            ack = AckMessage.from_json(data.decode())
            self.session_key = self.auth.process_ack(ack)
            self.peer_public_key = self.auth.peer_public_key

            log.info(
                "[%s] === AUTHENTICATED with %s ===",
                self.vehicle_id, self.peer_id,
            )
            with self._conn_lock:
                self._conn = conn
            self._start_comm_threads(conn)

        except AuthError as exc:
            log.error("[%s] Handshake FAILED: %s", self.vehicle_id, exc)
            conn.close()

    # ── Handshake (Responder) ─────────────────────────────────────

    def _run_handshake_responder(self, conn: socket.socket) -> None:
        """Execute the 4-step handshake as RESPONDER."""
        try:
            # Step 1 — receive HELLO
            data = recv_framed(conn)
            hello = HelloMessage.from_json(data.decode())

            # Step 2 — process HELLO, send CHALLENGE
            challenge = self.auth.process_hello(hello)
            send_framed(conn, challenge.to_json().encode())
            self.peer_id = hello.vehicle_id

            # Step 3 — receive RESPONSE
            data = recv_framed(conn)
            response = ResponseMessage.from_json(data.decode())

            # Step 4 — process RESPONSE, send ACK
            ack = self.auth.process_response(response, hello)
            send_framed(conn, ack.to_json().encode())
            self.session_key = self.auth.session_key
            self.peer_public_key = self.auth.peer_public_key

            log.info(
                "[%s] === AUTHENTICATED with %s ===",
                self.vehicle_id, self.peer_id,
            )
            with self._conn_lock:
                self._conn = conn
            self._start_comm_threads(conn)

        except AuthError as exc:
            log.error("[%s] Handshake FAILED: %s", self.vehicle_id, exc)
            conn.close()

    # ── BSM Communication ─────────────────────────────────────────

    def _start_comm_threads(self, conn: socket.socket) -> None:
        """Spin up the BSM send and receive loops."""
        threading.Thread(
            target=self._bsm_send_loop, args=(conn,), daemon=True
        ).start()
        threading.Thread(
            target=self._receive_loop, args=(conn,), daemon=True
        ).start()

    def _bsm_send_loop(self, conn: socket.socket) -> None:
        """Send one BSM every ``bsm_interval`` seconds."""
        while self.running:
            try:
                self._seq += 1
                bsm = BasicSafetyMessage(
                    vehicle_id=self.vehicle_id,
                    speed_kmh=round(random.uniform(60, 100), 1),
                    heading_deg=45.0,
                    latitude=6.9271 + random.uniform(-0.001, 0.001),
                    longitude=79.8612 + random.uniform(-0.001, 0.001),
                    timestamp=time.time(),
                    sequence_num=self._seq,
                    brake_applied=random.random() < 0.1,
                    acceleration=round(random.uniform(-2, 3), 1),
                )
                wire = secure_send(bsm, self.session_key, self.private_key, self.logger)
                send_framed(conn, wire)
                log.info(
                    "[%s] BSM #%d sent: speed=%.1f km/h",
                    self.vehicle_id, self._seq, bsm.speed_kmh,
                )
                time.sleep(self.bsm_interval)
            except (ConnectionError, OSError):
                log.warning("[%s] Connection lost during send", self.vehicle_id)
                self._attempt_reconnection()
                break

    def _receive_loop(self, conn: socket.socket) -> None:
        """Continuously receive and verify BSMs from the peer.

        Includes rate limiting — if a sender exceeds 15 messages/second,
        excess messages are dropped to maintain availability.
        """
        while self.running:
            try:
                raw = recv_framed(conn)

                # ── Rate Limiting Check (Availability) ──
                # Before doing any expensive crypto, check if this sender
                # is flooding us.  Drop excess messages immediately.
                sender_id = self.peer_id or "unknown"
                if not self.rate_limiter.allow(sender_id):
                    continue  # silently drop — DoS protection

                bsm = secure_receive(
                    raw,
                    self.session_key,
                    self.peer_public_key,
                    self.replay_cache,
                    self.timestamp_validator,
                    self.logger,
                    last_seq=self._last_peer_seq,
                )
                self._last_peer_seq = bsm.sequence_num
                log.info(
                    "[%s] BSM #%d from %s: speed=%.1f km/h VERIFIED",
                    self.vehicle_id, bsm.sequence_num,
                    bsm.vehicle_id, bsm.speed_kmh,
                )
            except TamperError as exc:
                log.warning("[%s] TAMPER ALERT: %s", self.vehicle_id, exc)
            except (ReplayError, SequenceError) as exc:
                log.warning("[%s] REPLAY ALERT: %s", self.vehicle_id, exc)
            except ConnectionError:
                log.warning("[%s] Connection lost during receive", self.vehicle_id)
                self._attempt_reconnection()
                break

    # ── Auto-Reconnection (Availability) ──────────────────────────

    def _attempt_reconnection(self) -> None:
        """Try to re-establish the connection after a drop.

        If this node was the initiator (client), it reconnects to the
        peer and re-runs the full handshake.  If this node was the
        responder (server), it re-opens the accept loop to wait for
        the peer to reconnect.  This ensures temporary network failures
        do not permanently disrupt communication.
        """
        if not self.running:
            return

        # Close old connection cleanly
        with self._conn_lock:
            if self._conn:
                try:
                    self._conn.close()
                except OSError:
                    pass
                self._conn = None

        # Reset session state for a fresh handshake
        self.session_key = None
        self.peer_public_key = None

        # Re-create the AuthProtocol so nonce/state is fresh
        self.auth = AuthProtocol(
            self.vehicle_id, self.private_key, self.cert_pem, self.ca_cert_pem
        )
        self.replay_cache = ReplayCache()
        self._last_peer_seq = None

        if self._is_initiator and self._peer_host and self._peer_port:
            # Initiator: actively reconnect with exponential backoff
            max_retries = 10
            for attempt in range(1, max_retries + 1):
                if not self.running:
                    return
                wait = min(2 * attempt, 30)  # cap at 30 seconds
                log.info(
                    "[%s] AUTO-RECONNECT attempt %d/%d in %ds...",
                    self.vehicle_id, attempt, max_retries, wait,
                )
                time.sleep(wait)
                if self.connect_to_peer(self._peer_host, self._peer_port):
                    log.info("[%s] AUTO-RECONNECT successful!", self.vehicle_id)
                    return
            log.error(
                "[%s] AUTO-RECONNECT failed after %d attempts",
                self.vehicle_id, max_retries,
            )
        else:
            # Responder: re-open the accept loop and wait for peer
            log.info(
                "[%s] AUTO-RECONNECT: waiting for peer to reconnect...",
                self.vehicle_id,
            )
            threading.Thread(target=self._accept_loop, daemon=True).start()

    # ── Dashboard State ───────────────────────────────────────────

    def get_state(self) -> dict:
        """Return the current node state for the Flask dashboard."""
        from cryptography import x509

        cert_status = "VALID"
        cert_cn = self.vehicle_id
        cert_expiry = "N/A"
        try:
            cert = x509.load_pem_x509_certificate(self.cert_pem)
            na = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
            cert_expiry = na.strftime("%Y-%m-%d")
        except Exception:
            cert_status = "ERROR"

        return {
            "vehicle_id": self.vehicle_id,
            "cert_status": cert_status,
            "cert_cn": cert_cn,
            "cert_expiry": cert_expiry,
            "auth_status": "AUTHENTICATED" if self.session_key else "NOT_AUTHENTICATED",
            "peer_id": self.peer_id or "None",
            "session_active": self.session_key is not None,
            "recent_messages": self.logger.get_recent(20),
            "alerts": self.logger.get_alerts(),
            "stats": {
                "total_sent": self.logger.total_sent,
                "total_received": self.logger.total_received,
                "tamper_attempts_blocked": self.logger.tamper_blocked,
                "replay_attempts_blocked": self.logger.replay_blocked,
                "rate_limit_dropped": self.rate_limiter.total_dropped,
            },
        }

    def shutdown(self) -> None:
        """Gracefully stop the node."""
        self.running = False
        try:
            self.server_sock.close()
        except OSError:
            pass
        log.info("[%s] Shutdown complete.", self.vehicle_id)


# ── CLI & Main ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="V2V Vehicle Node")
    parser.add_argument("--vehicle-id", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True, help="Path to vehicle certificate PEM")
    parser.add_argument("--key", required=True, help="Path to vehicle private key PEM")
    parser.add_argument("--ca-cert", required=True, help="Path to CA certificate PEM")
    parser.add_argument("--peer-host", default=None, help="Host to connect to")
    parser.add_argument("--peer-port", type=int, default=None, help="Port to connect to")
    parser.add_argument("--bsm-interval", type=float, default=1.0)
    parser.add_argument("--dashboard-port", type=int, default=5000)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    node = VehicleNode(
        vehicle_id=args.vehicle_id,
        port=args.port,
        cert_path=args.cert,
        key_path=args.key,
        ca_cert_path=args.ca_cert,
        bsm_interval=args.bsm_interval,
        dashboard_port=args.dashboard_port,
    )

    # Start Flask dashboard in background
    try:
        from dashboard.app import create_app

        app = create_app(node)
        threading.Thread(
            target=lambda: app.run(
                host="0.0.0.0", port=args.dashboard_port, debug=False, use_reloader=False
            ),
            daemon=True,
        ).start()
        log.info(
            "[%s] Dashboard at http://localhost:%d",
            args.vehicle_id, args.dashboard_port,
        )
    except ImportError:
        log.warning("Dashboard not available (flask not installed or app missing)")

    # Start TCP server
    node.start_server()

    # If --peer-host is set, connect as initiator; otherwise wait for peer
    if args.peer_host and args.peer_port:
        time.sleep(1)  # give the server thread time to start
        node.connect_to_peer(args.peer_host, args.peer_port)
    else:
        log.info("[%s] Waiting for incoming peer connection...", args.vehicle_id)

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down...")
        node.shutdown()


if __name__ == "__main__":
    main()
