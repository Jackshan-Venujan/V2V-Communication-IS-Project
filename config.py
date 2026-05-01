# Path to the CA certificate
CA_CERT_PATH = "ca/certs/ca_cert.pem"

# Path to the CA private key
CA_KEY_PATH = "ca/certs/ca_key.pem"

# Directory to store certificates
CERTS_DIR = "ca/certs"

# Port for Vehicle A
DEFAULT_VEHICLE_A_PORT = 9001

# Port for Vehicle B
DEFAULT_VEHICLE_B_PORT = 9002

# Port for Dashboard
DEFAULT_DASHBOARD_PORT = 5000

# Interval between Basic Safety Messages
BSM_INTERVAL_SECONDS = 1.0

# Window for detecting replay attacks
REPLAY_WINDOW_SECONDS = 5.0

# Duration to cache nonces for replay protection
NONCE_CACHE_DURATION = 300

# Maximum age of a timestamp before it's considered invalid
MAX_TIMESTAMP_AGE = 5.0
