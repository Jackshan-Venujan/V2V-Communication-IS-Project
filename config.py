"""Shared configuration constants for the V2V security simulation."""

# ── Network Configuration ──────────────────────────────────────────
VEHICLE_A_PORT = 9001          # TCP port Vehicle A listens on
VEHICLE_B_PORT = 9002          # TCP port Vehicle B listens on
DASHBOARD_A_PORT = 5001        # Flask dashboard for Vehicle A
DASHBOARD_B_PORT = 5002        # Flask dashboard for Vehicle B

# ── Certificate Paths ──────────────────────────────────────────────
CA_CERT_PATH = "ca/certs/ca_cert.pem"
CA_KEY_PATH = "ca/certs/ca_key.pem"
VEHICLE_A_CERT = "ca/certs/vehicle-a_cert.pem"
VEHICLE_A_KEY = "ca/certs/vehicle-a_key.pem"
VEHICLE_B_CERT = "ca/certs/vehicle-b_cert.pem"
VEHICLE_B_KEY = "ca/certs/vehicle-b_key.pem"

# ── Security Parameters ────────────────────────────────────────────
REPLAY_WINDOW_SECONDS = 300    # Nonces remembered for 5 minutes
TIMESTAMP_MAX_AGE = 5.0        # Messages older than 5 seconds are rejected
BSM_SEND_INTERVAL = 1.0        # Send a BSM every 1 second

# ── Crypto Settings ────────────────────────────────────────────────
AES_KEY_LENGTH = 32            # 256 bits (AES-256)
NONCE_LENGTH = 12              # 96 bits (AES-GCM standard nonce size)
EC_CURVE = "secp256r1"         # NIST P-256 curve (same as TLS 1.3)
SESSION_KEY_INFO = b"v2v-session-key-v1"  # HKDF info string

# ── Simulation Settings ────────────────────────────────────────────
SIMULATED_LATITUDE = 6.9271    # Colombo, Sri Lanka
SIMULATED_LONGITUDE = 79.8612
SPEED_RANGE = (60.0, 100.0)    # km/h for simulated vehicle
