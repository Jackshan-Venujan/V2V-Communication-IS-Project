# 🚗 V2V Security Project — Beginner/Intermediate Implementation Guide

> **Your goal:** Build a working, secure Vehicle-to-Vehicle communication system — on ONE machine, with NO Docker, NO MQTT — using Python sockets. This guide gives you **ready-to-use AI prompts** for every file you need to create.

---

## 📖 What You're Building (The Big Picture)

Imagine two cars on a road talking to each other wirelessly. Car A says "I'm braking hard!" — Car B receives this message, verifies it's authentic (not a hacker pretending to be Car A), decrypts it, and alerts the driver.

**The security challenge:** How does Car B know the message really came from Car A and wasn't faked or tampered with?

**The solution:** Digital certificates (like a passport), encryption (like a sealed envelope), and digital signatures (like a wax seal that breaks if tampered).

---

## 🗂️ Your Final Project Structure

```
v2v_security/
├── ca/
│   ├── ca.py                    ← Step 2: The "passport office" that issues IDs to vehicles
│   ├── issue_cert.py            ← Step 2: Issues a certificate to a specific vehicle
│   ├── verify_cert.py           ← Step 2: Checks if a certificate is valid
│   └── certs/                   ← Generated files (ca_cert.pem, vehicle certs)
├── crypto/
│   └── crypto.py                ← Step 3: All encryption/signing functions
├── protocol/
│   ├── auth_protocol.py         ← Step 4: The "handshake" between two vehicles
│   └── v2v_protocol.py          ← Step 5: Secure message sending/receiving
├── node/
│   └── vehicle_node.py          ← Step 6: The main vehicle program
├── dashboard/
│   ├── app.py                   ← Step 7: Flask web server
│   └── templates/
│       └── dashboard.html       ← Step 7: The visual dashboard page
├── attacks/
│   ├── replay_attack.py         ← Step 8a: Demonstrates replay attack detection
│   ├── tamper_attack.py         ← Step 8b: Demonstrates tamper detection
│   └── mitm_attack.py           ← Step 8c: Demonstrates MitM detection
├── tests/
│   ├── test_crypto.py           ← Step 9: Tests for crypto functions
│   ├── test_auth.py             ← Step 9: Tests for the handshake
│   └── evaluate_security.py     ← Step 10: Measures security performance
├── requirements.txt
└── config.py
```

---

## ⚙️ Step 1 — Environment Setup (Do This Yourself, No Prompt Needed)

This is the one step you do manually. It takes about 5 minutes.

> ⚠️ **Windows users:** Use **PowerShell** (not Command Prompt). Search "PowerShell" in your Start menu and open it. All commands below are for PowerShell.

```powershell
# 1. Create your project folder
mkdir v2v_security
cd v2v_security

# 2. Create a virtual environment (an isolated Python sandbox for this project)
python -m venv venv

# 3. Activate it — you MUST do this every time you open a new PowerShell window
.\venv\Scripts\Activate.ps1

# If you get an error about "running scripts is disabled", run this ONCE first:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Then try the activate command again.

# 4. Install all libraries
pip install cryptography flask requests pytest

# 5. Create the folder structure (PowerShell supports mkdir with paths directly)
mkdir ca\certs, crypto, protocol, node, dashboard\templates, attacks, tests
```

**What is a virtual environment?**
Think of it like a separate room for your project. All the Python libraries you install go into that room and don't interfere with other projects. When you type `.\venv\Scripts\Activate.ps1`, you "enter" that room. You'll see `(venv)` appear at the start of your prompt — that means it's active.

---

## 🏛️ Step 2 — Certificate Authority (The Passport Office)

### What Is a Certificate Authority (CA)?

**Analogy:** When you travel internationally, you show your passport. The passport was issued by your government (the trusted authority). The border officer trusts you because they trust your government. Your government is the **Certificate Authority (CA)**.

In V2V:
- The CA creates its own "master key" (private key) and "master stamp" (public certificate)
- When Vehicle A needs to join the network, the CA issues it a **signed certificate** — like issuing a passport
- When Vehicle B receives a message from Vehicle A, it checks: "Was this certificate signed by the CA I trust?" If yes → trust Vehicle A

### What Files Does This Step Create?

| File | Purpose |
|------|---------|
| `ca.py` | Creates the CA's own master keys and root certificate |
| `issue_cert.py` | Issues a certificate to a vehicle (like printing a passport) |
| `verify_cert.py` | Checks if a certificate is valid |

---

### 📋 PROMPT 2A — `ca/ca.py`

> Copy this entire prompt and paste it into Claude, ChatGPT, or any AI assistant:

```
Create a Python file called 'ca/ca.py' for a beginner-level Vehicle-to-Vehicle (V2V) security simulation.

This file is the Certificate Authority (CA) — the trusted "passport office" that gives digital certificates to vehicles.

WHAT IT MUST DO:
1. Generate an ECDSA P-256 key pair for the CA (private key + public key)
   - ECDSA P-256 = Elliptic Curve Digital Signature Algorithm, using the NIST P-256 curve
   - Use: from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
   
2. Create a self-signed X.509 certificate for the CA itself
   - Subject: CN=V2V-Root-CA, O=V2V-Security-Lab
   - Valid for 10 years from today
   - Key usage: Certificate Sign
   - Basic constraint: CA=True (this marks it as a Certificate Authority, not a regular certificate)
   
3. Save two files into 'ca/certs/' folder:
   - ca_cert.pem (the CA's public certificate — share this with all vehicles)
   - ca_key.pem (the CA's private key — keep this secret!)

4. Print a human-readable summary showing:
   - Subject, Issuer, Serial Number, Valid From, Valid To, Key type

REQUIREMENTS:
- Use ONLY the 'cryptography' library (PyCA) — no other crypto libraries
- Add a docstring to every function explaining: what it does, what arguments it takes, what it returns
- Use Python type hints (e.g., def generate_ca_key() -> EllipticCurvePrivateKey:)
- Use the 'logging' module for all output (not print), with format: [TIMESTAMP] LEVEL: message
- Wrap all operations in try/except blocks with helpful error messages
- Include an if __name__ == '__main__': block that runs the CA setup

BEGINNER-FRIENDLY COMMENTS:
- Add a plain-English comment above EVERY code block explaining what it does
- For example: # Generate a cryptographically random key pair using the P-256 elliptic curve
- Explain what PEM format is in a comment (Privacy Enhanced Mail — a text-based format for storing keys)

EXPECTED TERMINAL OUTPUT when you run 'python ca/ca.py':
[2024-01-15 10:23:01] INFO: Generating CA key pair (ECDSA P-256)...
[2024-01-15 10:23:01] INFO: CA key pair generated.
[2024-01-15 10:23:01] INFO: Creating self-signed root certificate...
[2024-01-15 10:23:01] INFO: Certificate details:
  Subject  : CN=V2V-Root-CA, O=V2V-Security-Lab
  Issuer   : CN=V2V-Root-CA (self-signed)
  Serial   : 0x3A7B2C...
  Valid From: 2024-01-15
  Valid To  : 2034-01-15
  Key Type : ECDSA P-256
[2024-01-15 10:23:01] INFO: Saved: ca/certs/ca_cert.pem
[2024-01-15 10:23:01] INFO: Saved: ca/certs/ca_key.pem
[2024-01-15 10:23:01] INFO: CA initialised successfully. Share ca_cert.pem with all vehicles.
```

---

### 📋 PROMPT 2B — `ca/issue_cert.py`

```
Create a Python file called 'ca/issue_cert.py' for a beginner-level V2V security simulation.

This file issues a digital certificate to a vehicle — like the passport office printing a passport for a citizen.

WHAT IT MUST DO:
1. Accept command-line arguments:
   - --vehicle-id   (e.g., "vehicle-a" or "vehicle-b")
   - --output-dir   (folder to save the certificate, e.g., "ca/certs")
   
2. Load the CA's private key from 'ca/certs/ca_key.pem'
   Load the CA's certificate from 'ca/certs/ca_cert.pem'

3. Generate a NEW ECDSA P-256 key pair for this vehicle
   (Every vehicle gets its own unique key pair — like every person gets a unique passport)

4. Create an X.509 certificate for this vehicle, signed by the CA:
   - Subject: CN={vehicle_id}, O=V2V-Security-Lab
   - Valid for 1 year from today
   - Key usage: Digital Signature
   - The CA signs this certificate with its private key
   
5. Save two files:
   - {vehicle_id}_cert.pem  (the vehicle's certificate — this is its "passport")
   - {vehicle_id}_key.pem   (the vehicle's private key — keep secret!)
   
6. Print the certificate fingerprint (SHA-256 hash) and serial number

REQUIREMENTS:
- Use ONLY the 'cryptography' library
- Use argparse for CLI arguments
- Add docstrings and type hints to every function
- Add plain-English comments explaining each step
- Handle errors gracefully (e.g., if CA cert file not found, print a helpful message)

EXAMPLE USAGE:
python ca/issue_cert.py --vehicle-id vehicle-a --output-dir ca/certs
python ca/issue_cert.py --vehicle-id vehicle-b --output-dir ca/certs

EXPECTED OUTPUT:
[INFO] Loading CA certificate and key...
[INFO] Generating key pair for vehicle-a...
[INFO] Creating certificate for vehicle-a...
[INFO] Certificate signed by CA.
[INFO] Saved: ca/certs/vehicle-a_cert.pem
[INFO] Saved: ca/certs/vehicle-a_key.pem
[INFO] Fingerprint (SHA-256): 3a:f2:b1:...
[INFO] Serial: 0xA4B2C3D4
```

---

### 📋 PROMPT 2C — `ca/verify_cert.py`

```
Create a Python file called 'ca/verify_cert.py' for a beginner-level V2V security simulation.

This file checks whether a certificate is valid — like a border officer checking your passport.

WHAT IT MUST DO:
1. Accept command-line arguments:
   - --cert     (path to the certificate to check, e.g., "ca/certs/vehicle-a_cert.pem")
   - --ca-cert  (path to the CA certificate, e.g., "ca/certs/ca_cert.pem")

2. Perform these checks:
   a) SIGNATURE CHECK: Was this certificate signed by the CA we trust?
      (Uses the CA's public key to verify the signature on the vehicle's certificate)
   b) DATE CHECK: Is the certificate currently valid (not expired, not future-dated)?
   c) SUBJECT CHECK: What entity does this certificate belong to?

3. Print a clear VALID or INVALID result with the reason

REQUIREMENTS:
- Use ONLY the 'cryptography' library
- Add detailed comments explaining what each check does and why it matters
- Return exit code 0 for valid, 1 for invalid (useful for scripts)

EXAMPLE USAGE:
python ca/verify_cert.py --cert ca/certs/vehicle-a_cert.pem --ca-cert ca/certs/ca_cert.pem

EXPECTED OUTPUT (valid case):
[CHECKING] ca/certs/vehicle-a_cert.pem
[OK] Signature valid — signed by V2V-Root-CA
[OK] Date valid — expires 2025-01-15
[OK] Subject: CN=vehicle-a, O=V2V-Security-Lab
RESULT: CERTIFICATE IS VALID ✓

EXPECTED OUTPUT (invalid case):
[CHECKING] fake_cert.pem
[FAIL] Signature invalid — NOT signed by V2V-Root-CA
RESULT: CERTIFICATE IS INVALID ✗
```

---

## 🔐 Step 3 — Cryptographic Module

### What Is This?

This is your **cryptography toolbox**. Instead of writing crypto code everywhere, you write all crypto functions once here, then import them wherever needed.

**The three main tools you'll use:**

| Tool | Analogy | Purpose |
|------|---------|---------|
| AES-256-GCM | A locked box only you and the recipient can open | Encrypts messages so eavesdroppers can't read them |
| ECDSA | A wax seal that breaks if tampered | Signs messages so receivers can detect forgery |
| ECDH | A secret colour-mixing trick (Diffie-Hellman) | Two vehicles agree on a shared encryption key without ever sending it |

**The ECDH colour-mixing analogy (really important to understand):**
1. Alice and Bob both start with the same public colour (yellow)
2. Alice adds her secret colour (red) → gets orange. Bob adds his secret (blue) → gets green
3. They swap orange and green over the internet (anyone can see this)
4. Alice mixes green + her secret red → brown. Bob mixes orange + his secret blue → brown
5. **Both got the same brown!** An eavesdropper saw yellow, orange, green — but can't compute brown without knowing red OR blue

This is how two vehicles agree on an encryption key without a hacker intercepting it.

---

### 📋 PROMPT 3 — `crypto/crypto.py`

```
Create a Python file called 'crypto/crypto.py' for a beginner-level V2V security simulation.

This is the cryptographic toolbox — all encryption, signing, and key exchange functions in one place.

IMPLEMENT EXACTLY THESE FUNCTIONS with full docstrings, type hints, and error handling:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION 1: aes_gcm_encrypt
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:

Purpose: Encrypt a message so only someone with the key can read it.

How it works:
- key must be exactly 32 bytes (256 bits)
- Generate a random 12-byte nonce using os.urandom(12)
  IMPORTANT: Never reuse a nonce with the same key! This would break the encryption completely.
- Use AESGCM from cryptography.hazmat.primitives.ciphers.aead
- Return: (ciphertext, nonce, auth_tag)
  - ciphertext: the encrypted message (same length as plaintext)
  - nonce: the random value used (12 bytes) — receiver needs this to decrypt
  - auth_tag: last 16 bytes of AESGCM output — proves no tampering occurred

Add this comment: # The auth_tag is AES-GCM's built-in tamper detection. 
                  # If even one bit of ciphertext changes, decryption will fail.

Raise ValueError if key is not 32 bytes.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION 2: aes_gcm_decrypt
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:

Purpose: Decrypt a message and verify it wasn't tampered with.

How it works:
- Reassemble: encrypted_blob = ciphertext + tag (AESGCM expects them joined)
- Call aesgcm.decrypt(nonce, encrypted_blob, None)
- If the tag doesn't match (i.e., message was tampered with), AESGCM raises InvalidTag
- Catch InvalidTag and raise a custom DecryptionError with message: "Message authentication failed — possible tampering detected"
- Return plaintext bytes

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION 3: generate_ecdh_keypair
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def generate_ecdh_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:

Purpose: Generate a fresh key pair for key exchange (new pair for every session).

How it works:
- Use generate_private_key(SECP256R1(), default_backend())
- Return (private_key, public_key)

Add comment: # We generate a NEW key pair each session (ephemeral).
             # This provides "Forward Secrecy": even if an old key leaks later,
             # past sessions can't be decrypted because this key no longer exists.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION 4: ecdh_shared_secret
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def ecdh_shared_secret(my_private_key: EllipticCurvePrivateKey, 
                        peer_public_key: EllipticCurvePublicKey) -> bytes:

Purpose: Compute the shared secret from my private key and peer's public key.
         Both vehicles end up with the same secret without ever sending it!

How it works:
- Use ECDH from cryptography.hazmat.primitives.asymmetric.ec
- Call my_private_key.exchange(ECDH(), peer_public_key)
- Returns 32 bytes (the shared secret)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION 5: derive_session_key
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def derive_session_key(shared_secret: bytes, nonce_a: bytes, nonce_b: bytes) -> bytes:

Purpose: Turn the ECDH shared secret into a proper AES encryption key.
         Raw shared secrets aren't safe to use directly as keys — HKDF "cleans" them.

How it works:
- Use HKDF from cryptography.hazmat.primitives.kdf.hkdf
- algorithm: SHA256
- length: 32 (for AES-256)
- salt: nonce_a + nonce_b (using both nonces makes the key unique per session)
- info: b"v2v-session-key-v1"
- Return 32-byte derived key

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION 6: ecdsa_sign
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def ecdsa_sign(private_key: EllipticCurvePrivateKey, message: bytes) -> bytes:

Purpose: Create a digital signature proving this message came from you.
         Like a wax seal — anyone can verify it's yours, but can't fake it.

How it works:
- Use private_key.sign(message, ECDSA(SHA256()))
- Returns DER-encoded signature bytes
- The signature is unique to: (this message) + (this private key)
- Anyone with the matching public key can verify it

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION 7: ecdsa_verify
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def ecdsa_verify(public_key: EllipticCurvePublicKey, message: bytes, signature: bytes) -> bool:

Purpose: Check if a signature is valid for this message and this public key.
         Returns True if authentic, False if forged or tampered.

How it works:
- Call public_key.verify(signature, message, ECDSA(SHA256()))
- This raises InvalidSignature if the signature doesn't match
- Catch InvalidSignature and return False (don't raise — just return False)
- Return True if no exception

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION 8: Serialization helpers
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def serialize_public_key(pub_key: EllipticCurvePublicKey) -> bytes:
    # Convert public key to PEM bytes (for sending over network or saving to file)
    
def load_public_key(pem_data: bytes) -> EllipticCurvePublicKey:
    # Load a public key from PEM bytes

def load_private_key(pem_data: bytes) -> EllipticCurvePrivateKey:
    # Load a private key from PEM bytes (no password needed for our simulation)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CUSTOM EXCEPTIONS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CryptoError(Exception): pass
class DecryptionError(CryptoError): pass
class SignatureError(CryptoError): pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEMO __main__ BLOCK:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Add a demonstration block that runs when the file is executed directly:

if __name__ == '__main__':
    print("=== CRYPTO MODULE DEMONSTRATION ===")
    
    # 1. ECDH key exchange demo
    print("\n[TEST 1] ECDH Key Exchange")
    # Generate key pairs for Vehicle A and Vehicle B
    # Each computes shared_secret using the other's public key
    # Verify both secrets match
    # Print: "Vehicle A secret == Vehicle B secret: TRUE"
    
    # 2. Session key derivation
    print("\n[TEST 2] Session Key Derivation")
    # Derive session key from shared secret and two random nonces
    # Print: "Session key (hex): ..." + length
    
    # 3. AES-GCM encryption/decryption
    print("\n[TEST 3] AES-GCM Encrypt/Decrypt")
    # Encrypt the message b"Hello from Vehicle A!"
    # Decrypt it
    # Verify it matches original
    # Print: "Decrypted: Hello from Vehicle A! ✓"
    
    # 4. ECDSA sign/verify
    print("\n[TEST 4] ECDSA Sign/Verify")
    # Sign a test message
    # Verify signature with matching public key → should return True
    # Verify signature with wrong public key → should return False
    # Print both results
    
    # 5. Tamper detection
    print("\n[TEST 5] Tamper Detection")
    # Encrypt a message
    # Flip one byte in the ciphertext
    # Try to decrypt → should raise DecryptionError
    # Print: "Tampered message correctly rejected ✓"

IMPORTANT: Use the 'cryptography' (PyCA) library throughout. Import from:
- cryptography.hazmat.primitives.asymmetric.ec
- cryptography.hazmat.primitives.ciphers.aead (AESGCM)
- cryptography.hazmat.primitives.kdf.hkdf (HKDF)
- cryptography.hazmat.primitives.hashes (SHA256)
- cryptography.hazmat.backends (default_backend)
- cryptography.hazmat.primitives.serialization (for PEM format)
- cryptography.exceptions (InvalidSignature, InvalidTag)
```

---

## 🤝 Step 4 — Authentication Protocol (The Handshake)

### What Is the Handshake?

**Analogy:** Two spies meeting for the first time. Neither trusts the other yet. They need to prove their identities. The protocol is:

1. **HELLO** → Spy A shows their credentials and a random number ("my badge number is 42")
2. **CHALLENGE** → Spy B shows their credentials and signs both numbers as proof ("I'm Spy B, and I sign 42+71 with my secret ink")
3. **RESPONSE** → Spy A verifies Spy B's signature and signs back ("Confirmed. Here's my half of our secret key")
4. **ACK** → Spy B confirms session is established ("Session open. Here's my half of our secret key")

After step 4, both have the **same session key** (from the ECDH exchange in steps 3 & 4) without ever sending the key itself. Every future message is encrypted with this key.

### Why Do We Need Nonces?

**Nonce = "Number Used Once"**

**Replay attack problem:** What if a hacker records Spy A's HELLO message and replays it tomorrow to impersonate A? The receiver would think it's a fresh message!

**Nonce solution:** Each HELLO contains a random 256-bit number. The receiver stores seen nonces and rejects duplicates. The timestamp also helps — if a message is older than 5 seconds, reject it.

---

### 📋 PROMPT 4 — `protocol/auth_protocol.py`

```
Create a Python file called 'protocol/auth_protocol.py' for a beginner-level V2V security simulation.

This file implements the 4-step mutual authentication handshake between two vehicles.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 1: MESSAGE DATACLASSES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Use Python dataclasses. Each message must have to_json() and from_json() methods
for easy serialization over the network.

@dataclass
class HelloMessage:
    # Step 1 of handshake: Initiator announces itself
    vehicle_id: str          # e.g., "vehicle-a"
    certificate_pem: str     # Vehicle's X.509 certificate in PEM text format
    nonce: str               # Random 32 bytes as hex string (64 hex chars)
                             # (prevents replay attacks)
    timestamp: float         # time.time() — Unix timestamp in seconds
    msg_type: str = "HELLO"  # Constant, identifies message type

@dataclass  
class ChallengeMessage:
    # Step 2: Responder proves its identity and challenges the initiator
    vehicle_id: str          # Responder's ID
    certificate_pem: str     # Responder's certificate
    nonce: str               # Responder's random nonce
    signed_nonces: str       # ECDSA signature of (initiator_nonce + responder_nonce) as hex
                             # This proves responder has its private key
    timestamp: float
    msg_type: str = "CHALLENGE"

@dataclass
class ResponseMessage:
    # Step 3: Initiator proves its identity and starts key exchange
    signed_nonces: str       # ECDSA signature of (initiator_nonce + responder_nonce) as hex
    ecdh_public_key_pem: str # Initiator's ephemeral ECDH public key (for key exchange)
    timestamp: float
    msg_type: str = "RESPONSE"

@dataclass
class AckMessage:
    # Step 4: Responder completes key exchange
    ecdh_public_key_pem: str # Responder's ephemeral ECDH public key
    session_established: bool = True
    msg_type: str = "ACK"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 2: REPLAY PROTECTION CLASSES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ReplayCache:
    """
    Stores recently seen nonces to detect replay attacks.
    
    How it works:
    - When we receive a message, we check if its nonce is in the cache
    - If yes: REPLAY ATTACK — reject the message
    - If no: add nonce to cache and process message
    - Nonces expire after window_seconds (default 300 seconds = 5 minutes)
    """
    def __init__(self, window_seconds: int = 300):
        # Store nonces as: {nonce_string: expiry_timestamp}
        pass
    
    def check_and_add(self, nonce: str) -> None:
        """
        Check if nonce was seen before. If yes, raise ReplayError.
        If no, add it to the cache.
        Also clean up expired nonces.
        """
        pass
    
    def _cleanup(self) -> None:
        """Remove expired nonces from cache."""
        pass

class TimestampValidator:
    """
    Rejects messages with timestamps outside the acceptable window.
    
    Why: An old message could be a replay attack.
    Example: max_age_seconds=5 means we reject any message older than 5 seconds.
    """
    def __init__(self, max_age_seconds: float = 5.0):
        pass
    
    def validate(self, timestamp: float) -> None:
        """
        Check if timestamp is recent enough.
        Raise StaleMessageError if: abs(time.time() - timestamp) > max_age_seconds
        """
        pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 3: THE MAIN AUTH PROTOCOL CLASS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AuthProtocol:
    """
    Implements the 4-step V2V mutual authentication handshake.
    
    Both vehicles run this class. One is the "initiator" (starts connection),
    one is the "responder" (accepts the connection).
    """
    def __init__(self, vehicle_id: str, private_key, certificate_pem: bytes, ca_cert_pem: bytes):
        """
        Args:
            vehicle_id: This vehicle's ID (e.g., "vehicle-a")
            private_key: This vehicle's ECDSA private key (for signing)
            certificate_pem: This vehicle's X.509 certificate in PEM format
            ca_cert_pem: The CA's certificate (for verifying peer's certificate)
        """
        self.vehicle_id = vehicle_id
        self.private_key = private_key
        self.certificate_pem = certificate_pem
        self.ca_cert_pem = ca_cert_pem
        self.replay_cache = ReplayCache()
        self.timestamp_validator = TimestampValidator(max_age_seconds=5.0)
        self.my_nonce: str = ""           # Our nonce (set when we send HELLO or CHALLENGE)
        self.peer_nonce: str = ""         # Peer's nonce (received in their message)
        self.session_key: bytes | None = None  # Set after successful handshake
        self._ecdh_private_key = None     # Our ephemeral ECDH key pair
    
    def build_hello(self) -> HelloMessage:
        """
        Build Step 1 — HELLO message.
        
        Creates our nonce (32 random bytes as hex string) and stores it
        in self.my_nonce for use when verifying the CHALLENGE later.
        """
        pass
    
    def process_hello(self, msg: HelloMessage) -> ChallengeMessage:
        """
        Process received HELLO (responder side). Build CHALLENGE response.
        
        Steps:
        1. Validate timestamp (reject if > 5 seconds old)
        2. Check nonce in replay cache (reject if seen before)
        3. Verify peer's certificate signature against CA certificate
           (Confirm the certificate was really issued by our CA)
        4. Store peer's nonce in self.peer_nonce
        5. Generate our own nonce (self.my_nonce)
        6. Sign (peer_nonce_bytes + our_nonce_bytes) with our private key
           (This proves we hold our private key without revealing it)
        7. Return ChallengeMessage
        
        Add detailed comments explaining WHY each step prevents a specific attack.
        """
        pass
    
    def process_challenge(self, msg: ChallengeMessage) -> ResponseMessage:
        """
        Process received CHALLENGE (initiator side). Build RESPONSE.
        
        Steps:
        1. Validate timestamp, check replay cache
        2. Verify peer's certificate against CA
        3. Verify the signed_nonces: peer should have signed (my_nonce + their_nonce)
           - Get peer's public key from their certificate
           - Verify signature over (my_nonce_bytes + peer_nonce_bytes)
           - If signature fails: REJECT (someone is impersonating the vehicle)
        4. Generate our ephemeral ECDH key pair (self._ecdh_private_key)
        5. Sign (my_nonce_bytes + peer_nonce_bytes) with our private key
        6. Return ResponseMessage with our ECDH public key
        """
        pass
    
    def process_response(self, msg: ResponseMessage, original_hello: HelloMessage) -> AckMessage:
        """
        Process RESPONSE (responder side). Complete handshake. Build ACK.
        
        Steps:
        1. Validate timestamp
        2. Verify signed_nonces: initiator signed (their_nonce + my_nonce)
        3. Generate our ephemeral ECDH key pair
        4. Load initiator's ECDH public key from msg.ecdh_public_key_pem
        5. Compute shared secret: ecdh_shared_secret(our_priv_key, their_pub_key)
        6. Derive session key: derive_session_key(shared_secret, nonce_a, nonce_b)
           where nonce_a = initiator's nonce, nonce_b = our nonce
        7. Store session key in self.session_key
        8. Return AckMessage with our ECDH public key
        """
        pass
    
    def process_ack(self, msg: AckMessage) -> bytes:
        """
        Process ACK (initiator side). Derive session key. Handshake complete!
        
        Steps:
        1. Load responder's ECDH public key from msg.ecdh_public_key_pem
        2. Compute shared secret using our ECDH private key and their public key
        3. Derive the SAME session key (using same nonces, same derivation)
           - Both vehicles now have identical session keys without ever sending it!
        4. Store in self.session_key
        5. Return session_key bytes
        
        Add comment explaining why both vehicles get the same key (ECDH mathematics).
        """
        pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HELPER: Certificate verification function
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def verify_certificate_against_ca(cert_pem: str, ca_cert_pem: bytes) -> EllipticCurvePublicKey:
    """
    Verify a certificate was signed by the CA.
    Returns the certificate's public key if valid.
    Raises CertificateError if invalid.
    
    Steps:
    1. Load the certificate from PEM bytes
    2. Load the CA certificate
    3. Get the CA's public key
    4. Use ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, ECDSA(SHA256()))
    5. Also check: cert.not_valid_before <= now <= cert.not_valid_after
    6. Return the certificate's subject public key info
    """
    pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CUSTOM EXCEPTIONS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class AuthError(Exception): pass
class ReplayError(AuthError): pass
class StaleMessageError(AuthError): pass
class CertificateError(AuthError): pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEMO __main__ BLOCK:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Simulate a full handshake between two AuthProtocol instances in the same process:
- Load real certificates from ca/certs/ folder
- Create AuthProtocol instance for vehicle-a (initiator)
- Create AuthProtocol instance for vehicle-b (responder)
- Run: hello → challenge → response → ack
- Verify both session keys are identical
- Print step-by-step log showing each message exchange

REQUIREMENTS:
- Import crypto functions from: from crypto.crypto import (ecdsa_sign, ecdsa_verify, 
  generate_ecdh_keypair, ecdh_shared_secret, derive_session_key, 
  serialize_public_key, load_public_key)
- Add logging at INFO level for each step of the handshake
- Use json.dumps/loads for message serialization (to_json returns JSON string, 
  from_json is a classmethod that takes JSON string)
```

---

## 📦 Step 5 — V2V Message Protocol (Secure Messages)

### What Is a BSM?

BSM = Basic Safety Message. It's what vehicles broadcast to each other:

```python
# A BSM looks like this:
{
    "vehicle_id": "vehicle-a",
    "speed_kmh": 72.3,
    "heading_deg": 45.0,
    "latitude": 6.9271,
    "longitude": 79.8612,
    "timestamp": 1706000000.123,
    "sequence_num": 42,
    "brake_applied": False
}
```

**"Sign-then-Encrypt" — the order matters:**
1. **Sign first:** Attach your ECDSA signature to the plaintext BSM
2. **Encrypt after:** Wrap the (BSM + signature) in AES-GCM encryption

Why not encrypt-then-sign? Because then someone could strip your signature off one ciphertext and attach it to another, causing confusion about who signed what.

---

### 📋 PROMPT 5 — `protocol/v2v_protocol.py`

```
Create a Python file called 'protocol/v2v_protocol.py' for a beginner-level V2V security simulation.

This file handles secure creation, sending, and receiving of V2V safety messages.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DATACLASS 1: BasicSafetyMessage (BSM)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@dataclass
class BasicSafetyMessage:
    """
    The standard vehicle safety broadcast message (inspired by SAE J2735).
    
    In real V2V systems, these are broadcast 10 times per second.
    In our simulation, we send one per second.
    """
    vehicle_id: str          # Pseudonymous vehicle ID (not real license plate)
    speed_kmh: float         # Speed in km/h
    heading_deg: float       # Compass heading 0-360 (0=North, 90=East)
    latitude: float          # GPS latitude (decimal degrees)
    longitude: float         # GPS longitude (decimal degrees)
    timestamp: float         # time.time() — used for replay detection
    sequence_num: int        # Incremented each message — detects missing messages
    brake_applied: bool      # True if brakes are engaged (SAFETY CRITICAL!)
    acceleration: float      # m/s^2 (positive=accelerating, negative=braking)
    
    def to_bytes(self) -> bytes:
        """Serialize to JSON bytes for signing/encryption."""
        pass
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'BasicSafetyMessage':
        """Deserialize from JSON bytes."""
        pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DATACLASS 2: SecureBSM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@dataclass
class SecureBSM:
    """
    A BSM that has been signed and encrypted.
    This is what actually travels over the network.
    
    Structure: AES-GCM( BSM_bytes + ECDSA_signature )
    """
    ciphertext: bytes        # Encrypted (BSM + signature)
    nonce: bytes             # 12-byte AES-GCM nonce
    auth_tag: bytes          # 16-byte AES-GCM authentication tag
    signature: bytes         # ECDSA signature over the PLAINTEXT BSM
                             # (signed BEFORE encryption)
    sender_id: str           # Vehicle ID (unencrypted, for routing)
    sequence_num: int        # Copy of BSM sequence number (for replay check before decrypt)
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes for network transmission.
        Use struct or json with base64 encoding for binary fields."""
        pass
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SecureBSM':
        """Deserialize from network bytes."""
        pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CLASS: MessageLogger
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class MessageLogger:
    """
    Records all sent and received messages with their security status.
    Used by the Flask dashboard to display recent activity.
    """
    def __init__(self, max_messages: int = 50):
        self._messages: list[dict] = []
        self._alerts: list[dict] = []
    
    def log_sent(self, bsm: BasicSafetyMessage) -> None:
        """Log an outgoing BSM with timestamp."""
        pass
    
    def log_received(self, bsm: BasicSafetyMessage, security_props: dict) -> None:
        """
        Log an incoming BSM with security verification results.
        
        security_props example:
        {
            "authenticated": True,    # Certificate was valid
            "encrypted": True,        # Message was AES-GCM encrypted
            "integrity_verified": True,  # Signature was valid
            "replay_protected": True  # Nonce/timestamp check passed
        }
        """
        pass
    
    def log_alert(self, alert_type: str, details: str) -> None:
        """Log a security alert (replay/tamper detected)."""
        pass
    
    def get_recent(self, count: int = 20) -> list[dict]:
        """Return the most recent N messages."""
        pass
    
    def get_alerts(self) -> list[dict]:
        """Return all security alerts."""
        pass
    
    def clear_alerts(self) -> None:
        pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION: secure_send
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def secure_send(
    bsm: BasicSafetyMessage,
    session_key: bytes,
    signing_key,            # ECDSA private key
    logger: MessageLogger
) -> bytes:
    """
    Securely prepare a BSM for transmission.
    
    Process (Sign-then-Encrypt):
    Step 1: Serialize BSM to bytes
    Step 2: ECDSA sign the BSM bytes using signing_key
            Comment: # We sign the PLAINTEXT so the signature proves content
                     # before encryption. Signing after encryption would allow
                     # someone to swap signatures between messages.
    Step 3: AES-GCM encrypt (bsm_bytes + delimiter + signature_bytes) using session_key
            Simple delimiter: use length-prefixing:
            - 4 bytes for BSM length
            - BSM bytes
            - signature bytes (rest)
    Step 4: Build SecureBSM with ciphertext, nonce, auth_tag, signature, sender_id
    Step 5: Log the sent message
    Step 6: Return SecureBSM.to_bytes()
    
    Raise CryptoError if any step fails.
    """
    pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FUNCTION: secure_receive
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def secure_receive(
    data: bytes,
    session_key: bytes,
    peer_verify_key,        # ECDSA public key of the sender
    replay_cache: ReplayCache,     # Import from auth_protocol
    timestamp_validator: TimestampValidator,  # Import from auth_protocol
    logger: MessageLogger
) -> BasicSafetyMessage:
    """
    Receive, decrypt, verify, and parse a SecureBSM.
    
    Process:
    Step 1: Parse SecureBSM from raw bytes
    Step 2: Check replay cache with nonce (from the BSM after decryption)
            Actually, for BSMs we use timestamp + sequence_num for replay
            Check: sequence_num > last seen seq_num from this sender
    Step 3: AES-GCM decrypt ciphertext using session_key, nonce, auth_tag
            If decryption fails (tag mismatch): raise TamperError
            Comment: # AES-GCM will fail here if even 1 bit was changed
    Step 4: Unpack decrypted bytes into (bsm_bytes, signature_bytes)
    Step 5: ECDSA verify signature against peer_verify_key
            If invalid: raise TamperError
    Step 6: Parse BasicSafetyMessage from bsm_bytes
    Step 7: Validate BSM timestamp with timestamp_validator
    Step 8: Log received message with all security properties
    Step 9: Return the verified BSM
    
    Log a security alert for any exception before re-raising it.
    """
    pass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CUSTOM EXCEPTIONS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class TamperError(Exception): pass    # Message was modified in transit
class ReplayError(Exception): pass   # Duplicate message detected
class SequenceError(Exception): pass # Sequence number out of order

IMPORTS TO USE:
from crypto.crypto import aes_gcm_encrypt, aes_gcm_decrypt, ecdsa_sign, ecdsa_verify
from protocol.auth_protocol import ReplayCache, TimestampValidator

Add beginner-friendly comments throughout explaining why each security step matters.
```

---

## 🖥️ Step 6 — Main Vehicle Node

### What Is This?

This is the **main program** for each vehicle. It:
1. Starts a TCP server (listens for incoming connections)
2. Connects to the peer vehicle and runs the handshake
3. Sends BSMs every second
4. Receives and verifies BSMs from the peer

**Simple threading model (beginner-friendly):**
- Thread 1: Accept incoming connections (blocking)
- Thread 2: Send BSMs every second
- Thread 3: Receive and verify BSMs

---

### 📋 PROMPT 6 — `node/vehicle_node.py`

```
Create a Python file called 'node/vehicle_node.py' for a beginner-level V2V security simulation.

This is the main vehicle node — it handles the network connection, authentication, and message exchange.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SIMPLIFIED ARCHITECTURE (no complex threading):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
We use THREE threads:
1. Main thread: starts server, then connects to peer (or waits for connection)
2. Send thread (daemon): sends a BSM every bsm_interval seconds
3. Receive thread (daemon): loops receiving and verifying BSMs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HELPER FUNCTION: send_framed / recv_framed
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TCP is a stream — it doesn't know where messages begin and end.
We use "length-prefixed framing" to solve this:

def send_framed(sock: socket.socket, data: bytes) -> None:
    """
    Send data with a 4-byte length prefix.
    Format: [LENGTH (4 bytes, big-endian)] [DATA (LENGTH bytes)]
    
    Example: sending b"hello" (5 bytes):
    Sends: b'\x00\x00\x00\x05hello'
    """
    length = len(data)
    sock.sendall(struct.pack('>I', length) + data)
    # '>I' = big-endian unsigned 32-bit integer
    # This tells the receiver exactly how many bytes to read

def recv_framed(sock: socket.socket) -> bytes:
    """
    Receive a framed message (reads the length prefix first, then the data).
    Blocks until the full message arrives.
    """
    # Read 4-byte length prefix
    length_bytes = _recv_exactly(sock, 4)
    length = struct.unpack('>I', length_bytes)[0]
    # Read exactly 'length' bytes
    return _recv_exactly(sock, length)

def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket. Loop until we have all of them."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        data += chunk
    return data

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CLASS: VehicleNode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class VehicleNode:
    def __init__(
        self,
        vehicle_id: str,
        port: int,
        cert_path: str,
        key_path: str,
        ca_cert_path: str,
        bsm_interval: float = 1.0,    # Send a BSM every N seconds
        dashboard_port: int = 5000
    ):
        """
        Load certificates, initialise all components.
        
        Steps:
        1. Load certificate PEM from cert_path (read file as bytes)
        2. Load private key from key_path (read file, parse with load_pem_private_key)
        3. Load CA certificate from ca_cert_path
        4. Create AuthProtocol instance
        5. Create MessageLogger instance
        6. Create ReplayCache and TimestampValidator
        7. Set up server socket:
           - socket.AF_INET, socket.SOCK_STREAM
           - setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
           (SO_REUSEADDR lets us restart quickly without "Address already in use" errors)
        8. Set: self.session_key = None, self.peer_public_key = None,
                self.peer_id = None, self.running = True
        """
        pass
    
    def start_server(self) -> None:
        """
        Start listening for incoming connections.
        
        Steps:
        1. self.server_sock.bind(('', self.port))
        2. self.server_sock.listen(1)  — we only expect 1 peer
        3. Log: "[vehicle_id] Listening on port {port}..."
        4. Start _accept_loop in a daemon thread
        """
        pass
    
    def _accept_loop(self) -> None:
        """Accept one incoming connection and run handshake as RESPONDER."""
        conn, addr = self.server_sock.accept()
        log.info(f"[{self.vehicle_id}] Peer connected from {addr}")
        self._run_handshake_responder(conn)
    
    def connect_to_peer(self, host: str, port: int) -> bool:
        """
        Connect to peer and run handshake as INITIATOR.
        
        Steps:
        1. Create new socket and connect to (host, port)
        2. Log: "Connecting to {host}:{port}..."
        3. _run_handshake_initiator(conn)
        4. Return True on success, False on failure
        5. Log each step with timing
        """
        pass
    
    def _run_handshake_initiator(self, conn: socket.socket) -> None:
        """
        Run the 4-step handshake as the INITIATOR (the one who connects).
        
        STEP 1: Build HELLO and send it
            hello = self.auth.build_hello()
            send_framed(conn, hello.to_json().encode())
            log.info(f"Sent HELLO (nonce={hello.nonce[:8]}...)")
        
        STEP 2: Receive CHALLENGE
            data = recv_framed(conn)
            challenge = ChallengeMessage.from_json(data.decode())
            log.info(f"Received CHALLENGE from {challenge.vehicle_id}")
        
        STEP 3: Process CHALLENGE, build RESPONSE
            response = self.auth.process_challenge(challenge)
            send_framed(conn, response.to_json().encode())
            log.info("Sent RESPONSE with ECDH public key")
        
        STEP 4: Receive ACK
            data = recv_framed(conn)
            ack = AckMessage.from_json(data.decode())
            self.session_key = self.auth.process_ack(ack)
            log.info(f"MUTUAL AUTHENTICATION COMPLETE. Session key derived.")
        
        After handshake: store peer_public_key, peer_id, start send/receive loops
        
        Raise AuthError and close connection on any failure.
        """
        pass
    
    def _run_handshake_responder(self, conn: socket.socket) -> None:
        """
        Run the 4-step handshake as the RESPONDER (the one who accepts connection).
        
        STEP 1: Receive HELLO
            data = recv_framed(conn)
            hello = HelloMessage.from_json(data.decode())
        
        STEP 2: Process HELLO, build CHALLENGE, send it
            challenge = self.auth.process_hello(hello)
            send_framed(conn, challenge.to_json().encode())
        
        STEP 3: Receive RESPONSE
            data = recv_framed(conn)
            response = ResponseMessage.from_json(data.decode())
        
        STEP 4: Process RESPONSE, build ACK, send it
            ack = self.auth.process_response(response, hello)
            send_framed(conn, ack.to_json().encode())
            self.session_key = self.auth.session_key
        
        After: store peer info, start send/receive loops
        """
        pass
    
    def _start_comm_threads(self, conn: socket.socket) -> None:
        """Start the BSM send loop and receive loop in background threads."""
        t_send = threading.Thread(target=self._bsm_send_loop, args=(conn,), daemon=True)
        t_recv = threading.Thread(target=self._receive_loop, args=(conn,), daemon=True)
        t_send.start()
        t_recv.start()
    
    def _bsm_send_loop(self, conn: socket.socket) -> None:
        """
        Send a BSM every bsm_interval seconds.
        
        BSM content: use slightly randomized values to simulate movement:
        - speed_kmh: random between 60 and 100
        - heading_deg: fixed (e.g., 45.0 for northeast)
        - latitude/longitude: use realistic Sri Lanka coordinates + tiny random offset
        - sequence_num: increment each time
        - brake_applied: False (randomly True sometimes for demo)
        
        For each BSM:
        1. Create BasicSafetyMessage
        2. Call secure_send() from v2v_protocol
        3. send_framed(conn, result)
        4. Log: "BSM #{seq} sent: speed={speed} km/h"
        5. time.sleep(self.bsm_interval)
        """
        pass
    
    def _receive_loop(self, conn: socket.socket) -> None:
        """
        Continuously receive and verify BSMs.
        
        For each received message:
        1. recv_framed(conn) to get raw bytes
        2. secure_receive() to decrypt and verify
        3. Log: "BSM #{seq} received from {peer}: speed={speed}, AUTHENTICATED ✓"
        4. On TamperError: log ALERT, add to alerts list
        5. On ReplayError: log ALERT
        6. On ConnectionError: break loop (peer disconnected)
        """
        pass
    
    def get_state(self) -> dict:
        """
        Return current node state for the Flask dashboard.
        
        Returns:
        {
            "vehicle_id": self.vehicle_id,
            "cert_status": "VALID",  # or "EXPIRED"
            "cert_cn": "vehicle-a",
            "cert_expiry": "2025-01-15",
            "auth_status": "AUTHENTICATED",  # or "NOT_AUTHENTICATED"
            "peer_id": self.peer_id or "None",
            "session_active": self.session_key is not None,
            "messages_sent": ...,
            "messages_received": ...,
            "recent_messages": self.logger.get_recent(20),
            "alerts": self.logger.get_alerts(),
            "stats": {
                "total_sent": ...,
                "total_received": ...,
                "tamper_attempts_blocked": ...,
                "replay_attempts_blocked": ...
            }
        }
        """
        pass
    
    def shutdown(self) -> None:
        """Gracefully stop the node."""
        self.running = False
        self.server_sock.close()
        log.info(f"[{self.vehicle_id}] Shutdown complete.")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CLI (argparse) AND MAIN:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='V2V Vehicle Node')
    parser.add_argument('--vehicle-id', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--ca-cert', required=True)
    parser.add_argument('--peer-host', default=None)   # If set, connect to this host
    parser.add_argument('--peer-port', type=int, default=None)
    parser.add_argument('--bsm-interval', type=float, default=1.0)
    parser.add_argument('--dashboard-port', type=int, default=5000)
    
    Main logic:
    1. Create VehicleNode instance
    2. Start Flask dashboard in daemon thread:
       from dashboard.app import create_app
       app = create_app(node)
       threading.Thread(target=app.run, kwargs={'port': dashboard_port, 'debug': False}, daemon=True).start()
    3. node.start_server()
    4. If --peer-host given: node.connect_to_peer(peer_host, peer_port)
       If not: log "Waiting for peer connection..."
    5. Keep main thread alive: while True: time.sleep(1)
    6. Handle KeyboardInterrupt: node.shutdown()

IMPORTS NEEDED:
import socket, threading, struct, time, argparse, logging
from crypto.crypto import load_private_key, load_public_key
from protocol.auth_protocol import AuthProtocol, HelloMessage, ChallengeMessage, ResponseMessage, AckMessage, ReplayCache, TimestampValidator, AuthError
from protocol.v2v_protocol import BasicSafetyMessage, MessageLogger, secure_send, secure_receive, TamperError, ReplayError
```

---

## 📊 Step 7 — Flask Dashboard

### 📋 PROMPT 7A — `dashboard/app.py`

```
Create a Python file called 'dashboard/app.py' for a beginner-level V2V security simulation.

This creates a simple web server that shows the vehicle's status in a browser.

def create_app(node) -> Flask:
    """
    Create and configure the Flask application.
    
    'node' is the VehicleNode instance — we call node.get_state() to get data.
    
    ROUTES:
    
    GET /
        Render 'dashboard.html' template
    
    GET /api/state
        Return node.get_state() as JSON
        (Called every 3 seconds by the browser to refresh the dashboard)
    
    GET /api/alerts
        Return {'alerts': node.logger.get_alerts()} as JSON
    
    POST /api/clear-alerts
        Call node.logger.clear_alerts()
        Return {'status': 'cleared'}
    
    Add CORS headers (Access-Control-Allow-Origin: *) to all responses
    for development convenience.
    
    Return the Flask app object.
    """
    pass

Add: if __name__ == '__main__': app.run(debug=True, port=5000)

REQUIREMENTS:
- from flask import Flask, jsonify, render_template, request
- Keep it simple — no authentication on the dashboard needed for this project
- Add a comment explaining what each route does
```

---

### 📋 PROMPT 7B — `dashboard/templates/dashboard.html`

```
Create an HTML file called 'dashboard/templates/dashboard.html' for a V2V security monitoring dashboard.

DESIGN: Clean, professional, dark-themed monitoring dashboard. 
Use only plain HTML, CSS, and vanilla JavaScript — NO frameworks (no React, no Vue, no Bootstrap).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LAYOUT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Dark navy header bar: "V2V Security Dashboard — {vehicle_id}"
Subtitle: "Real-time secure vehicle communication monitor"

Three status cards in a row:
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Certificate     │ │ Authentication  │ │ Security Alerts │
│ Status          │ │ Status          │ │                 │
│ [VALID badge]   │ │ [AUTH badge]    │ │ Count: 0        │
│ CN: vehicle-a   │ │ Peer: vehicle-b │ │ "No alerts"     │
│ Expires: ...    │ │ Session: Active │ │ [Clear] button  │
└─────────────────┘ └─────────────────┘ └─────────────────┘

Statistics row: 4 numbers in boxes:
  Messages Sent | Messages Received | Attacks Blocked | Session Active

Recent Messages table (last 20, newest first):
Columns: Time | Speed | Heading | Brake | Auth ✓ | Encrypted ✓ | Integrity ✓ | Replay ✓

Footer: "Auto-refreshes every 3 seconds | Vehicle: {id} | Dashboard port: {port}"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COLOUR SCHEME:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Background: #0d1117 (very dark)
Card background: #161b22
Header: #1a237e (dark blue)
Text: #e6edf3
Accent green: #3fb950 (for VALID/AUTHENTICATED badges)
Accent red: #f85149 (for INVALID/alerts)
Accent yellow: #d29922 (for warnings)
Monospace font for IDs and hex values

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
JAVASCRIPT (auto-refresh):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
async function fetchState() {
    const response = await fetch('/api/state');
    const data = await response.json();
    updateDashboard(data);
}

function updateDashboard(data) {
    // Update vehicle_id in header
    // Update certificate status card:
    //   - Show green "VALID" badge if cert_status == "VALID", red "EXPIRED" otherwise
    //   - Show CN, expiry date
    // Update authentication card:
    //   - Show green "AUTHENTICATED" if auth_status == "AUTHENTICATED"
    //   - Show peer vehicle ID
    //   - Show "Session Key: Active" or "Session Key: None"
    // Update alerts card:
    //   - Show alert count
    //   - If alerts.length > 0: make card flash red (CSS animation)
    //   - Show latest alert text
    // Update stats numbers
    // Update messages table:
    //   - Clear table body
    //   - For each message in data.recent_messages:
    //     - Add a row
    //     - For security properties: show ✓ (green) or ✗ (red)
    //     - If any security property is false: make row background yellow
}

setInterval(fetchState, 3000);  // Refresh every 3 seconds
fetchState();  // Load immediately on page open

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CSS for blinking alert:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@keyframes blink-red {
    0%, 100% { border-color: #f85149; box-shadow: 0 0 10px #f85149; }
    50% { border-color: transparent; box-shadow: none; }
}
.alert-active { animation: blink-red 1s infinite; }
```

---

## 💥 Step 8 — Attack Demonstrations

### 📋 PROMPT 8A — `attacks/replay_attack.py`

```
Create 'attacks/replay_attack.py' for a beginner-level V2V security demonstration.

This script shows what happens when an attacker captures a message and replays it later.

HOW A REPLAY ATTACK WORKS:
1. Attacker listens on the network and captures a valid BSM from Vehicle A
2. 10 seconds later, attacker sends the EXACT SAME bytes to Vehicle B
3. WITHOUT protection, Vehicle B would accept it as legitimate
4. WITH our protection, Vehicle B rejects it because:
   - The timestamp is 10 seconds old (outside our 5-second window)
   - The nonce was already seen and is in the replay cache

WHAT THIS SCRIPT DOES:
- Simulates the attack IN-PROCESS (no real network needed for the demo)
- Creates a legitimate BSM, signs and encrypts it
- Calls secure_receive() immediately (should PASS)
- Waits 6 seconds
- Calls secure_receive() again with the SAME bytes (should FAIL with ReplayError)
- Prints a clear report showing the attack was blocked

Print a banner:
╔══════════════════════════════════════╗
║    REPLAY ATTACK DEMONSTRATION       ║
╚══════════════════════════════════════╝

Steps to demonstrate:
1. Set up: create CA, issue certs, create session key (load from ca/certs/)
2. Vehicle A creates a BSM: speed=80, heading=45, timestamp=now
3. Vehicle A signs and encrypts it: raw_bytes = secure_send(bsm, session_key, signing_key, logger)
4. Print: [CAPTURED] BSM at {timestamp}, nonce={nonce[:8]}..., seq={seq}
5. Vehicle B receives it (first time): secure_receive(raw_bytes, ...)
   Print: [OK] First delivery ACCEPTED ✓
6. Wait 6 seconds (time.sleep(6))
   Print: [WAITING] 6 seconds... (beyond 5-second replay window)
7. Vehicle B receives it (replay): try secure_receive(raw_bytes, ...)
   - Should raise ReplayError or TamperError
   Print: [BLOCKED] Replay attempt REJECTED ✗
   Print: Reason: {error message}

FINAL REPORT:
══════════════════════════════════════
 RESULT: REPLAY ATTACK BLOCKED ✓
══════════════════════════════════════
 Security properties that stopped this:
 ✓ Timestamp validation (5-second window)
 ✓ Nonce cache (256-bit nonces stored for 5 minutes)

Add detailed comments explaining WHAT checks caught the replay and WHY they work.

IMPORTS:
from crypto.crypto import *
from protocol.auth_protocol import ReplayCache, TimestampValidator
from protocol.v2v_protocol import BasicSafetyMessage, MessageLogger, secure_send, secure_receive, ReplayError
```

---

### 📋 PROMPT 8B — `attacks/tamper_attack.py`

```
Create 'attacks/tamper_attack.py' for a beginner-level V2V security demonstration.

This script shows what happens when an attacker modifies a message in transit.

HOW A TAMPER ATTACK WORKS:
1. Vehicle A sends an encrypted BSM
2. Attacker intercepts the bytes and flips 3 bits in the ciphertext
3. Attacker forwards the modified bytes to Vehicle B
4. Vehicle B tries to decrypt → AES-GCM's authentication tag no longer matches
   → Decryption fails → Message rejected

WHAT THIS SCRIPT DOES:
- Creates a legitimate BSM, encrypts it
- Modifies 3 bytes at random positions in the ciphertext
- Attempts to decrypt the modified ciphertext
- Shows the DecryptionError being raised

Print banner:
╔══════════════════════════════════════╗
║    TAMPER ATTACK DEMONSTRATION       ║
╚══════════════════════════════════════╝

Steps:
1. Create and encrypt a BSM (same setup as replay demo)
2. Print original ciphertext first 20 bytes in hex
3. Flip 3 random bytes:
   positions = [random.randint(0, len(ciphertext)-1) for _ in range(3)]
   For each position: ciphertext[pos] ^= 0xFF  (XOR with 0xFF flips all bits)
   Print: "Modified byte at position {pos}: 0x{before:02x} → 0x{after:02x}"
4. Attempt decryption of modified ciphertext
5. Should raise DecryptionError

FINAL REPORT:
══════════════════════════════════════
 RESULT: TAMPER ATTACK BLOCKED ✓
══════════════════════════════════════
 ✓ AES-256-GCM authentication tag mismatch
 ✓ Even 1 flipped bit invalidates the entire message
 ✓ ECDSA signature would also catch this after decryption

Comment: # This demonstrates "Authenticated Encryption" — AES-GCM doesn't just
         # encrypt, it creates a tamper-evident seal. The 16-byte auth tag is
         # computed over the entire ciphertext. Change one byte → tag doesn't match.
```

---

### 📋 PROMPT 8C — `attacks/mitm_attack.py`

```
Create 'attacks/mitm_attack.py' for a beginner-level V2V security demonstration.

This script shows how certificate verification stops Man-in-the-Middle attacks.

SCENARIO A — Certificate Replacement:
- Attacker intercepts Vehicle A's HELLO message
- Attacker generates a FAKE self-signed certificate (not signed by the CA)
- Attacker replaces Vehicle A's real certificate with the fake one
- Vehicle B checks: "Is this certificate signed by my trusted CA?"
- CA signature check fails → REJECTED

SCENARIO B — Relay Attack:
- Attacker relays all messages unchanged
- Vehicle B sends a CHALLENGE: "Sign these two nonces with your private key"
- Attacker doesn't have Vehicle A's private key
- Attacker cannot forge the RESPONSE → Authentication fails

WHAT THIS SCRIPT DOES:
In-process simulation of both scenarios.

Print banner:
╔══════════════════════════════════════╗
║  MAN-IN-THE-MIDDLE ATTACK DEMO       ║
╚══════════════════════════════════════╝

SCENARIO A:
1. Load Vehicle A's real HELLO message
2. Generate a fake ECDSA key pair (attacker's keys)
3. Create a fake self-signed certificate for "vehicle-a" using attacker's keys
4. Replace hello.certificate_pem with the fake certificate
5. Vehicle B calls verify_certificate_against_ca(fake_cert, ca_cert_pem)
6. Should raise CertificateError
Print: [SCENARIO A] BLOCKED — Fake certificate rejected by CA verification ✗

SCENARIO B:
1. Vehicle A sends authentic HELLO
2. Vehicle B sends CHALLENGE with nonce_b
3. Attacker tries to forge RESPONSE by signing with attacker's private key (not Vehicle A's)
4. Vehicle B verifies signature with Vehicle A's public key (from real certificate)
5. ecdsa_verify(vehicle_a_pub_key, nonces, attacker_signature) → returns False
Print: [SCENARIO B] BLOCKED — Forged signature rejected ✗

FINAL REPORT:
══════════════════════════════════════
 RESULT: BOTH ATTACK SCENARIOS BLOCKED ✓
══════════════════════════════════════
 ✓ X.509 certificates are CA-signed (can't be faked without CA private key)
 ✓ Challenge-response proves private key ownership
 ✓ Certificate replacement detected by CA signature verification
```

---

## 🧪 Step 9 — Tests

### 📋 PROMPT 9A — `tests/test_crypto.py`

```
Create 'tests/test_crypto.py' — unit tests for all functions in crypto/crypto.py.

Use pytest. Write tests for:

1. test_aes_gcm_encrypt_decrypt(): 
   Encrypt b"test message", decrypt it, verify it matches original.

2. test_aes_gcm_tamper_detection():
   Encrypt, flip one byte in ciphertext, try decrypt, assert DecryptionError is raised.

3. test_wrong_key_rejected():
   Encrypt with key A, try decrypt with key B, assert DecryptionError.

4. test_ecdsa_sign_verify():
   Sign b"hello", verify with matching public key → True.
   Verify same signature with different public key → False.

5. test_ecdh_both_sides_get_same_secret():
   Generate key pair A and key pair B.
   secret_a = ecdh_shared_secret(priv_a, pub_b)
   secret_b = ecdh_shared_secret(priv_b, pub_a)
   assert secret_a == secret_b

6. test_session_key_derivation():
   Derive session key from shared secret + two nonces.
   Assert it's 32 bytes.
   Assert different nonces produce different keys.

7. test_nonce_uniqueness():
   Generate 1000 nonces, assert no duplicates.
   (os.urandom is cryptographically random — duplicates are astronomically unlikely)

Add a docstring to each test explaining WHAT it tests and WHY it matters.
Use pytest.raises() for exception tests.
```

---

### 📋 PROMPT 9B — `tests/test_auth.py`

```
Create 'tests/test_auth.py' — integration tests for the authentication handshake.

SETUP (pytest fixture):
@pytest.fixture
def auth_pair():
    """Load real certificates and create two AuthProtocol instances."""
    # Load CA cert, vehicle-a cert/key, vehicle-b cert/key from ca/certs/
    # Return (auth_a, auth_b) — two AuthProtocol instances
    # Skip test if certs not found (with pytest.skip())

1. test_full_handshake(auth_pair):
   Run the complete 4-step handshake in-process.
   Assert both session keys are equal and not None.
   Assert session key length is 32 bytes.

2. test_replay_hello_rejected(auth_pair):
   Build a HELLO message, process it (first time should succeed).
   Process the SAME HELLO again → should raise ReplayError.

3. test_stale_timestamp_rejected(auth_pair):
   Build a HELLO, manually set timestamp to time.time() - 100 (100 seconds ago).
   Call process_hello → should raise StaleMessageError.

4. test_fake_certificate_rejected():
   Generate a fake self-signed certificate.
   Build a HELLO using the fake certificate.
   Call process_hello with a real AuthProtocol instance → should raise CertificateError.

5. test_forged_signature_rejected(auth_pair):
   Build a valid CHALLENGE message.
   Replace signed_nonces with a random hex string (invalid signature).
   Call process_challenge → should raise AuthError.
```

---

## 📈 Step 10 — Security Evaluation

### 📋 PROMPT 10 — `tests/evaluate_security.py`

```
Create 'tests/evaluate_security.py' — a security evaluation script that measures 
the performance of our V2V security system.

Print banner:
╔══════════════════════════════════════════════════════╗
║         V2V SECURITY EVALUATION REPORT               ║
╚══════════════════════════════════════════════════════╝

RUN THESE 5 TESTS AND PRINT A FORMATTED RESULTS TABLE:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TEST 1: Encryption Speed
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Generate a 32-byte key
- Encrypt 1000 test BSM payloads (use b"test BSM payload" * 10 as dummy data)
- Measure total time with time.perf_counter()
- Calculate: operations per second, MB/s
- PASS if > 500 ops/sec

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TEST 2: Signature Speed  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Generate an ECDSA key pair
- Sign 100 messages (ECDSA is slower than AES)
- Measure operations per second
- PASS if > 100 ops/sec

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TEST 3: Replay Detection Rate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Create ReplayCache with window_seconds=300
- Generate 100 unique nonces, add each to cache (should succeed)
- Try to add each nonce again (should all raise ReplayError)
- Count how many were caught
- PASS if 100/100 replays detected (100%)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TEST 4: Tamper Detection Rate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Create 50 valid encrypted messages
- Flip 1 byte in each ciphertext
- Attempt to decrypt each
- Count how many raised DecryptionError
- PASS if 50/50 tampered messages detected (100%)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TEST 5: Nonce Uniqueness
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Generate 10,000 nonces using os.urandom(32)
- Convert each to hex string, add to a set
- Check for duplicates (len(set) should == 10,000)
- PASS if 0 duplicates

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRINT RESULTS TABLE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
╔═══════════════════════════╦══════════════╦════════╦════════╗
║ Test                      ║ Result       ║ Target ║ Status ║
╠═══════════════════════════╬══════════════╬════════╬════════╣
║ Encryption Speed          ║ 2341 ops/s   ║ >500   ║ PASS ✓ ║
║ Signature Speed           ║ 187 ops/s    ║ >100   ║ PASS ✓ ║
║ Replay Detection Rate     ║ 100/100      ║ 100%   ║ PASS ✓ ║
║ Tamper Detection Rate     ║ 50/50        ║ 100%   ║ PASS ✓ ║
║ Nonce Uniqueness (10k)    ║ 0 collisions ║ 0      ║ PASS ✓ ║
╚═══════════════════════════╩══════════════╩════════╩════════╝

Overall: 5/5 tests PASSED

Also save results to 'tests/security_report.txt'.

Add comments explaining what each metric tells us about the system's security.
```

---

## 🚀 How to Run Everything (Windows — PowerShell)

> Open **separate PowerShell windows** for each terminal step below. In each new window, navigate to your project and activate the venv first.

### Step 0 — One-time setup (run in any PowerShell window)

```powershell
cd v2v_security
.\venv\Scripts\Activate.ps1

# Generate the CA (the "passport office")
python ca\ca.py

# Issue certificates to both vehicles
python ca\issue_cert.py --vehicle-id vehicle-a --output-dir ca\certs
python ca\issue_cert.py --vehicle-id vehicle-b --output-dir ca\certs

# Verify they were created correctly
python ca\verify_cert.py --cert ca\certs\vehicle-a_cert.pem --ca-cert ca\certs\ca_cert.pem
```

### Step 1 — PowerShell Window 1: Start Vehicle A

```powershell
cd v2v_security
.\venv\Scripts\Activate.ps1

python node\vehicle_node.py `
  --vehicle-id vehicle-a `
  --port 9001 `
  --cert ca\certs\vehicle-a_cert.pem `
  --key ca\certs\vehicle-a_key.pem `
  --ca-cert ca\certs\ca_cert.pem `
  --dashboard-port 5001
```

> 💡 The backtick `` ` `` is PowerShell's line-continuation character (like `\` on Linux).

### Step 2 — PowerShell Window 2: Start Vehicle B

```powershell
cd v2v_security
.\venv\Scripts\Activate.ps1

python node\vehicle_node.py `
  --vehicle-id vehicle-b `
  --port 9002 `
  --cert ca\certs\vehicle-b_cert.pem `
  --key ca\certs\vehicle-b_key.pem `
  --ca-cert ca\certs\ca_cert.pem `
  --peer-host 127.0.0.1 `
  --peer-port 9001 `
  --dashboard-port 5002
```

### Step 3 — Open Dashboards in your browser

```
http://localhost:5001   ← Vehicle A dashboard
http://localhost:5002   ← Vehicle B dashboard
```

### Step 4 — PowerShell Window 3: Run attack demos

```powershell
cd v2v_security
.\venv\Scripts\Activate.ps1

python attacks\replay_attack.py
python attacks\tamper_attack.py
python attacks\mitm_attack.py
```

### Step 5 — Run tests and security evaluation

```powershell
pytest tests\test_crypto.py -v
pytest tests\test_auth.py -v
python tests\evaluate_security.py
```

---

## 🔍 Understanding the Key Concepts

### Why 4 Steps for Authentication?

| Step | Who Acts | What Happens | Security Goal |
|------|----------|--------------|---------------|
| HELLO | Vehicle A → B | "Hi, here's my certificate and a random number" | B can verify A's identity |
| CHALLENGE | Vehicle B → A | "Here's my cert. I sign your number + mine" | A can verify B's identity AND B proves it has its private key |
| RESPONSE | Vehicle A → B | "I verify your signature. Here's my ECDH key" | B can verify A's private key AND key exchange begins |
| ACK | Vehicle B → A | "Here's my ECDH key. Session open!" | Key exchange complete — both have session key |

### Why Does AES-GCM Beat Tampering?

AES-GCM = AES + Galois Counter Mode

The "GCM" part generates a 128-bit **authentication tag** — a fingerprint of the ciphertext. If even **one bit** changes, the tag won't match. The receiver checks the tag BEFORE returning the decrypted data, so you can never see tampered content.

### Why ECDSA Over RSA?

| Property | RSA 2048-bit | ECDSA P-256 |
|----------|-------------|-------------|
| Key size | 2048 bits | 256 bits |
| Signature size | 256 bytes | ~71 bytes |
| Sign speed | ~1ms | ~0.1ms |
| Security level | 112-bit | 128-bit |

For V2V, vehicles need to verify many messages per second. ECDSA is 10x faster with smaller signatures.

---

## 📁 `config.py` — Shared Configuration

### 📋 PROMPT: `config.py`

```
Create 'config.py' — a shared configuration file for the V2V project.

NOTE FOR WINDOWS: Python's open() and the cryptography library both accept forward
slashes (/) in file paths on Windows — no need to change them to backslashes here.
Only PowerShell terminal commands need backslashes.

Define these constants with comments explaining each one:

# ── Network Configuration ──────────────────────────────────────────
VEHICLE_A_PORT = 9001      # TCP port Vehicle A listens on
VEHICLE_B_PORT = 9002      # TCP port Vehicle B listens on
DASHBOARD_A_PORT = 5001    # Flask dashboard for Vehicle A
DASHBOARD_B_PORT = 5002    # Flask dashboard for Vehicle B

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
SIMULATED_LATITUDE = 6.9271    # Kandy, Sri Lanka
SIMULATED_LONGITUDE = 80.6350
SPEED_RANGE = (60.0, 100.0)   # km/h for simulated vehicle
```

---

## 📝 `requirements.txt`

```
Create a 'requirements.txt' file with exactly these packages (no version pinning needed for simplicity):

cryptography      # PyCA: AES-GCM, ECDSA, ECDH, X.509 certificates
flask             # Lightweight web framework for the dashboard
requests          # HTTP client (optional, for testing dashboard API)
pytest            # Test runner

Install with: pip install -r requirements.txt
```

---

## 🪟 Windows-Specific Notes & Troubleshooting

**If Windows Firewall pops up asking to allow Python:**
Click **"Allow access"**. This is needed for the two vehicles to talk to each other over TCP on localhost.

**If you get `ModuleNotFoundError: No module named 'crypto'`:**
This happens because Python has a different built-in module called `crypto`. Rename your folder from `crypto` to `v2v_crypto` and update the import in every file from `from crypto.crypto import ...` to `from v2v_crypto.crypto import ...`.

Alternatively, when generating the AI code for `crypto.py`, add this note to each prompt:
> "Name the module folder `v2v_crypto` instead of `crypto` to avoid naming conflicts with Python's built-in `crypto` module on Windows."

**If `pytest` is not found:**
Run `pip install pytest` again with the venv active. Confirm with `where pytest` — it should show a path inside your `venv\Scripts\` folder.

**If you see `Address already in use` on port 9001/9002:**
Open Task Manager → Details tab → find `python.exe` processes → End Task on them. Or run:
```powershell
netstat -ano | findstr :9001
# Note the PID at the end, then:
taskkill /PID <the_pid_number> /F
```

**Line continuation in PowerShell:**
Use the backtick `` ` `` at the end of a line (not `\` like Linux). The prompts in this guide that show multi-line `python node\vehicle_node.py \` commands should use `` ` `` on Windows.

---

## ✅ Checklist — Are You Done?

Go through this before your demo (all commands in PowerShell with venv active):

- [ ] `python ca\ca.py` → Shows certificate details, creates PEM files
- [ ] `python ca\issue_cert.py --vehicle-id vehicle-a --output-dir ca\certs` → Creates vehicle cert
- [ ] `python ca\verify_cert.py --cert ca\certs\vehicle-a_cert.pem --ca-cert ca\certs\ca_cert.pem` → Shows VALID
- [ ] `python crypto\crypto.py` → All 5 demo tests pass
- [ ] `python protocol\auth_protocol.py` → Full handshake demo shows both keys match
- [ ] Vehicle A and B nodes start and authenticate successfully (see 4-step log)
- [ ] Dashboard at localhost:5001 shows green AUTHENTICATED status
- [ ] BSM messages appear in the dashboard table with all ✓ checkmarks
- [ ] `python attacks\replay_attack.py` → Shows BLOCKED
- [ ] `python attacks\tamper_attack.py` → Shows BLOCKED
- [ ] `python attacks\mitm_attack.py` → Shows both scenarios BLOCKED
- [ ] `pytest tests\ -v` → All tests pass
- [ ] `python tests\evaluate_security.py` → All 5 metrics PASS

---

*This guide was simplified from the original V2V Security complete guide. Docker, MQTT, two-laptop setup, HMAC-on-top-of-AES-GCM, and complex threading have been removed. The core security concepts — CA, certificates, AES-256-GCM, ECDSA, ECDH, replay detection — are all present and working.*

---
---

# 🧭 Design Rationale — Why These Methods? (Teaching & Presentation Guide)

> **Purpose of this section:** The first half of this guide tells you *what to build*. This half tells you *why each choice was made*, *what the alternatives were*, and *why we rejected them*. Use it to answer examiner / audience questions like *"Why ECDSA and not RSA?"* or *"Why encrypt AND sign — isn't one enough?"*
>
> Every claim below maps to real code in this project. File references: `crypto/crypto.py`, `ca/ca.py`, `ca/issue_cert.py`, `protocol/auth_protocol.py`, `protocol/v2v_protocol.py`, `node/vehicle_node.py`, `config.py`.

### 📌 One-Slide Summary — The Decision Matrix

| # | Decision | We Chose | Main Alternative | Why We Rejected the Alternative |
|---|----------|----------|------------------|---------------------------------|
| 1 | Elliptic curve | **NIST P-256 (secp256r1)** | RSA-2048 / P-384 / Curve25519 | RSA too big & slow; P-384 overkill; P-256 is the V2V/TLS standard curve |
| 2 | Digital signature | **ECDSA-SHA256** | RSA-PSS, Ed25519 | RSA slow & large; Ed25519 great but not X.509/V2V-standard default |
| 3 | Key exchange | **Ephemeral ECDH (ECDHE)** | Static ECDH, RSA key transport | Static/RSA-transport have **no forward secrecy** |
| 4 | Bulk encryption | **AES-256-GCM (AEAD)** | AES-CBC+HMAC, ChaCha20-Poly1305 | CBC+HMAC error-prone; ChaCha fine but no AES-NI advantage |
| 5 | Key derivation | **HKDF-SHA256** | Raw secret, plain SHA-256, PBKDF2 | Raw secret not uniform; plain hash has no salt/domain-separation; PBKDF2 is for *passwords* |
| 6 | Identity | **X.509 + custom Root CA** | Pre-shared keys, raw keys (TOFU) | PSK doesn't scale; TOFU is MITM-vulnerable on first contact |
| 7 | Authentication | **4-step mutual challenge-response** | One-way auth, plain cert exchange | One-way leaves one car unverified; cert alone doesn't prove key *possession* |
| 8 | Message order | **Sign-then-Encrypt** | Encrypt-then-Sign | Lets an attacker strip & re-attach signatures |
| 9 | Freshness | **Nonce cache + timestamp + sequence #** | Any single one of them | Each one alone has a gap the others close |
| 10 | Randomness | **`os.urandom` (CSPRNG)** | Python `random` module | `random` is predictable — fatal for keys/nonces |
| 11 | Transport | **TCP + length-prefix framing** | UDP broadcast, MQTT | Teaching simplicity; handshake needs reliable, ordered delivery |

---

## A. Asymmetric Cryptography Choices

### A1. Why the NIST P-256 curve (secp256r1)?

**What the code does:** Every key pair — CA, vehicles, and ephemeral session keys — uses `SECP256R1()` (`ca/ca.py`, `crypto.py:generate_ecdh_keypair`, `config.py: EC_CURVE = "secp256r1"`).

**Why P-256:**
- **128-bit security level** — breaking it needs ~2¹²⁸ operations, far beyond any computer for the foreseeable future.
- **It is the V2V industry curve.** The real automotive standard **IEEE 1609.2** (used by US/EU connected-vehicle systems) mandates ECDSA over **P-256 / P-384**. Choosing P-256 makes this project a faithful scale-model of the real thing.
- **Universal tooling.** The PyCA `cryptography` library, X.509, OpenSSL, and TLS 1.3 all support it natively — no custom code.

| Curve option | Security level | Speed | Verdict |
|---|---|---|---|
| **P-256 (chosen)** | 128-bit | Fast | ✅ Standard, fast, "enough" |
| P-384 / P-521 | 192 / 256-bit | Slower | ❌ Overkill for our threat model; wastes CPU vehicles broadcasting 10×/sec can't spare |
| Curve25519 / Ed25519 | ~128-bit | Fastest, misuse-resistant | ⚠️ Technically excellent, but **not the X.509/1609.2 default** — chosen against only for *standards alignment* |
| secp256k1 (Bitcoin's curve) | 128-bit | Fast | ❌ Designed for blockchains, not for TLS/automotive PKI |

**🎤 Talking point:** *"P-256 isn't the strongest curve available — it's the strongest curve we **need**, and it's the one real V2V systems actually use. Security engineering is matching strength to the threat, not maximizing a number."*

> **Honest nuance for advanced questions:** Some cryptographers prefer Curve25519 because its parameters were generated transparently, whereas the NIST P-curves' constants are less "explainable." For a standards-compliant V2V demo, P-256 is still the correct teaching choice — but mentioning this shows depth.

### A2. Why ECDSA for digital signatures (not RSA)?

**What the code does:** `crypto.py:ecdsa_sign / ecdsa_verify` sign with `ECDSA(SHA256)`. Used to sign CA→vehicle certificates, the handshake nonces, and every BSM.

**Why ECDSA:** A vehicle verifies *many* signatures per second (every neighbour's BSM). Signature/key size and speed dominate.

| Property | RSA-2048 | **ECDSA P-256 (chosen)** |
|---|---|---|
| Public key size | 256 bytes | **32 bytes** |
| Signature size | 256 bytes | **~71 bytes** |
| Sign speed | Slow | **~10× faster** |
| Security level | ~112-bit | **128-bit** |
| Bandwidth on a 10 Hz radio | Heavy | **Light** |

**Why not the alternatives:**
- **RSA-2048/3072** — every signature is 256+ bytes and signing is slow. On a channel broadcasting 10 messages/second, the larger signatures and slower math directly hurt. Rejected.
- **Ed25519 (EdDSA)** — actually *faster and more misuse-resistant* than ECDSA (deterministic, no risky per-signature random `k`). We didn't use it **only** because X.509 vehicle certificates and the IEEE 1609.2 standard are built around ECDSA. In a from-scratch design, Ed25519 would be a defensible upgrade.

**🎤 Talking point:** *"Same security as RSA, but the key is 8× smaller and the signature is 3.5× smaller. For a car that has to verify hundreds of messages a second from every car around it, that size and speed difference is the whole game."*

### A3. Why **ephemeral** ECDH (ECDHE) — and what is Forward Secrecy?

**What the code does:** `crypto.py:generate_ecdh_keypair` creates a **brand-new** ECDH key pair for **every handshake** (`protocol/auth_protocol.py:process_challenge / process_response`). These keys are used once and then discarded.

**Why ephemeral:** This gives **Forward Secrecy**. The session key is derived from keys that *no longer exist* after the session ends.

> **Scenario to explain in the presentation:** An attacker records all encrypted V2V traffic today and stores it. Six months later they steal a vehicle's long-term private key from its certificate.
> - With **static** keys → they can now decrypt all six months of recordings. 💀
> - With **ephemeral** keys → they get *nothing*. The keys that produced those session keys were thrown away. ✅

| Key exchange option | Forward secrecy? | Verdict |
|---|---|---|
| **Ephemeral ECDH (chosen)** | ✅ Yes | ✅ Past traffic stays safe even after a key theft |
| Static-static ECDH (reuse the certificate's keys) | ❌ No | ❌ One key theft retroactively breaks every past session |
| RSA key transport (one side picks the key, RSA-encrypts it) | ❌ No | ❌ This is exactly why **TLS 1.3 removed RSA key transport** |

**🎤 Talking point:** *"The long-term certificate key proves **who you are**. The ephemeral ECDH key creates **today's secret**. Keeping those two jobs separate is what makes a stolen identity key unable to unlock yesterday's conversations."*

---

## B. Symmetric Encryption Choices

### B1. Why AES-256-GCM (an AEAD cipher)?

**What the code does:** `crypto.py:aes_gcm_encrypt / aes_gcm_decrypt` use `AESGCM` from PyCA. Every BSM payload is encrypted with the session key.

**Why GCM specifically — it is an AEAD (Authenticated Encryption with Associated Data):** It does **two jobs in one pass**:
1. **Confidentiality** — encrypts the data so eavesdroppers see gibberish.
2. **Integrity** — produces a 128-bit **authentication tag**. Flip a single bit of the ciphertext and decryption *fails outright* — you never even see the tampered data.

Other reasons:
- **Hardware acceleration** — modern CPUs have AES-NI instructions, making AES-GCM extremely fast.
- **Standard** — AES-GCM is a default cipher suite in **TLS 1.3**.

| Cipher option | Integrity built in? | Risk / Cost | Verdict |
|---|---|---|---|
| **AES-256-GCM (chosen)** | ✅ Yes (one pass) | Nonce **must never repeat** | ✅ Fast, standard, integrity-included |
| AES-CBC + separate HMAC | ⚠️ Only if done right | Two keys, two steps; wrong order → **padding-oracle attacks** | ❌ Easy to implement insecurely |
| ChaCha20-Poly1305 | ✅ Yes | None major | ⚠️ Equally good — but no AES-NI advantage on our hardware |
| AES-CCM | ✅ Yes | Two-pass, slower | ⚠️ Used by IEEE 1609.2, but GCM is one-pass & parallelizable |
| Plain AES-CTR / AES-CBC (no MAC) | ❌ **No** | Attacker can flip bits undetected | ❌ Encryption without integrity is **not secure** |

**Why not the alternatives:**
- **AES-CBC + HMAC** — needs two keys and a *manual* "Encrypt-then-MAC" composition. Get the order wrong and you open a padding-oracle hole. GCM removes the chance to make that mistake.
- **ChaCha20-Poly1305** — genuinely just as secure. We picked AES-GCM because our target machines have AES-NI hardware and because it matches TLS 1.3's default. (ChaCha is the *better* pick for low-power devices *without* AES-NI — a good "it depends" answer.)
- **Plain CTR/CBC with no MAC** — gives confidentiality but **zero integrity**. Rejected immediately: an attacker could change "speed = 80" to "speed = 0" and you'd never know.

### B2. Why AES-**256** and not AES-128?

`config.py: AES_KEY_LENGTH = 32` (32 bytes = 256 bits). AES-128 is already considered unbreakable, but AES-256 costs almost nothing extra on modern CPUs and gives a larger safety margin (including a hedge against future quantum attacks, which roughly halve symmetric strength). When the price of "more" is near-zero, take it.

### B3. Why a 12-byte (96-bit) random nonce?

**What the code does:** `crypto.py:aes_gcm_encrypt` calls `os.urandom(12)` for every encryption (`config.py: NONCE_LENGTH = 12`).

- **96 bits is GCM's *native* nonce size.** NIST SP 800-38D processes a 96-bit IV directly; any other length goes through an extra hashing step. 12 bytes = the fast, standard path.
- **Random vs. counter:** A deterministic counter never repeats but needs both sides to track shared state. A random nonce needs no shared state — simpler and correct for a short-lived session.

> **The one rule you must state out loud:** *Never reuse a (key, nonce) pair.* GCM nonce reuse is **catastrophic** — it leaks the authentication key and lets an attacker forge messages. Random 96-bit nonces are safe well within a single session because the collision (birthday) probability stays negligible until ~2³² messages — far more than any V2V session sends before re-keying.

---

## C. Key Derivation

### C1. Why HKDF-SHA256 — why not use the ECDH secret directly?

**What the code does:** `crypto.py:derive_session_key` feeds the raw ECDH output into **HKDF-SHA256**: `salt = nonce_a + nonce_b`, `info = b"v2v-session-key-v1"`, `length = 32`.

**The problem HKDF solves:** The raw ECDH shared secret is the *x-coordinate of a point on the curve*. It is secret, but it is **not uniformly random** — some bit patterns are slightly more likely than others. AES keys must be uniformly random. HKDF's **extract-then-expand** design "cleans" the secret into a proper, uniform key.

The HKDF inputs each do a job:
- **`salt` = both nonces** — binds the key to *this specific session*. Same two cars handshaking twice ⇒ two different keys.
- **`info` = `"v2v-session-key-v1"`** — *domain separation*. If you later derived other keys from the same secret, the `info` string keeps them independent.

| KDF option | Right tool here? | Why / Why not |
|---|---|---|
| **HKDF-SHA256 (chosen)** | ✅ Yes | Purpose-built for **high-entropy** key material; adds salt + domain separation |
| Use the raw ECDH secret as the key | ❌ No | Not uniformly distributed — biased key bits |
| Plain `SHA256(secret)` | ❌ No | No salt → same secret always → same key; no domain separation; no extract/expand structure |
| PBKDF2 / scrypt / Argon2 | ❌ No | Those are **password** KDFs — *deliberately slow* to fight brute force on *low-entropy* input. ECDH output is already high-entropy; slow stretching just wastes CPU |

**🎤 Talking point:** *"Diffie-Hellman gives you a shared **secret**, not a shared **key**. HKDF is the standard, correct step that turns one into the other. Skipping it is a classic beginner mistake."*

---

## D. Identity & Public Key Infrastructure (PKI)

### D1. Why X.509 certificates and a custom Root CA?

**What the code does:** `ca/ca.py` builds a self-signed Root CA; `ca/issue_cert.py` issues a CA-signed X.509 certificate to each vehicle; `ca/verify_cert.py` and `auth_protocol.py:verify_certificate_against_ca` check them.

**The core problem:** A public key is just a number. How does Vehicle B know a public key *truly belongs to* Vehicle A and not an impostor? A certificate **binds an identity to a public key**, and the CA's signature makes that binding **trustworthy**.

| Identity option | Scales? | Verifies identity? | Verdict |
|---|---|---|---|
| **X.509 + Root CA (chosen)** | ✅ Yes | ✅ Yes (CA signature) | ✅ One trusted CA ⇒ trust anyone it signs |
| Pre-shared keys (every pair shares a secret) | ❌ No (n² keys) | ⚠️ Weakly | ❌ Doesn't scale; no real identity; key-distribution nightmare |
| Raw public keys / Trust-On-First-Use | ✅ Yes | ❌ **No** | ❌ First contact is unauthenticated → MITM walks straight in |
| Web-of-trust (PGP-style) | ⚠️ Partly | ⚠️ Fuzzy | ❌ No clear authority; too vague for safety-critical traffic |

**Why a CA wins:** A vehicle only has to pre-trust **one** thing — the CA certificate. Then it can instantly verify *any* vehicle the CA has ever signed, including ones it has never met. That is exactly the "passport / passport office" model.

**🎤 Talking point:** *"Pre-shared keys mean 1,000 cars need ~500,000 secret keys. A CA means 1,000 cars need to trust exactly **one** certificate. That's the whole reason PKI exists."*

### D2. Why a 10-year CA certificate but 1-year vehicle certificates?

`ca/ca.py` sets the CA valid for **10 years**; `ca/issue_cert.py` sets vehicles for **1 year**.

- The **CA is the trust anchor** — rotating it is disruptive (every vehicle must re-learn it), so it lives long and is guarded carefully.
- **Leaf (vehicle) certificates are short-lived** so that a compromised or stolen vehicle credential automatically stops working soon. Short lifetimes *limit the blast radius* of a compromise.

> **Real-world contrast (great for marks):** Production V2V (the **SCMS** — Security Credential Management System) goes much further — it issues **short-lived pseudonym certificates** that rotate frequently (even per-trip) so that an eavesdropper can't track *which* car is *which* over time. Our project uses one stable cert per car for teaching clarity, deliberately trading away that *privacy* feature.

### D3. Why ECDSA key usage flags differ (CA vs vehicle)?

`ca/ca.py` sets `BasicConstraints(ca=True)` + `key_cert_sign=True` — this certificate's *only* job is to sign other certificates. `ca/issue_cert.py` sets `ca=False` + `digital_signature=True` — a vehicle may sign messages but **may not** issue certificates. This enforces *least privilege*: even if a vehicle key leaks, it cannot mint fake vehicles.

---

## E. The Authentication Protocol

### E1. Why a 4-step **mutual** handshake (and not one-way)?

**What the code does:** `protocol/auth_protocol.py` runs HELLO → CHALLENGE → RESPONSE → ACK.

- **Why mutual:** In HTTPS, only the *server* proves identity (one-way). In V2V, **both peers are equally untrusted** — Car A must verify Car B *and* Car B must verify Car A. A fake "braking!" warning from an unverified car can cause a crash.
- **Why 4 messages:** Each pair of steps achieves one security goal:

| Steps | Goal achieved |
|---|---|
| HELLO + CHALLENGE | Both sides exchange and verify **certificates** (identity) |
| CHALLENGE + RESPONSE | Both sides **sign each other's nonce** — proving private-key *possession* (liveness) |
| RESPONSE + ACK | Both sides exchange **ephemeral ECDH public keys** — establishing the session key |

### E2. Why challenge-response with signed nonces — isn't showing the certificate enough?

**No — and this is a key teaching point.** A certificate is *public*. An attacker can copy Vehicle A's certificate from any recorded message. Presenting a certificate only proves *"I have a copy of A's certificate,"* not *"I am A."*

The fix: Vehicle B sends a fresh random **nonce** and demands *"sign this with your private key."* Only the real Vehicle A holds that private key, so only the real A can produce a valid signature over B's just-now-generated nonce. Because the nonce is fresh, a recorded old signature is useless.

> This pattern — exchange certificates, then prove key possession by signing fresh nonces, then do ephemeral DH — is essentially a teaching-simplified version of the real **Station-to-Station (STS) / SIGMA** protocols that underpin IPsec and TLS.

**Why we built it by hand instead of just calling a TLS library:** *Pedagogically.* Implementing the handshake exposes every moving part — nonces, certificate verification, signatures, key exchange. **In production you would absolutely use vetted TLS 1.3 or IEEE 1609.2**, never a hand-rolled protocol. Say this explicitly in your presentation; it shows you know the difference between a *learning model* and a *deployable system*.

---

## F. Message Security

### F1. Why "Sign-then-Encrypt" (not "Encrypt-then-Sign")?

**What the code does:** `protocol/v2v_protocol.py:secure_send` — Step 1 serialize BSM, Step 2 **ECDSA-sign the plaintext**, Step 3 **AES-GCM-encrypt** the (BSM + signature) together.

**Why this order:**
1. **The signature is bound to the actual message content.** It is computed over the real plaintext, so it provably attests to *that* data.
2. **It defeats signature-stripping / substitution.** With *Encrypt-then-Sign*, the signature sits on the *outside* of the ciphertext. An attacker could peel that signature off, wrap it around a *different* ciphertext, and re-sign — causing confusion about who authored what. Signing the plaintext first makes the signature inseparable from the content.
3. **It hides *who signed*.** The signature is *inside* the encryption, so an eavesdropper can't even see which vehicle authored a message — a small privacy bonus.

### F2. "AES-GCM already gives integrity — why *also* sign with ECDSA?"

This is the single best question an examiner can ask. The answer:

> The AES-GCM session key is **shared by both vehicles**. So a valid GCM tag only proves *"someone who knows the session key sent this"* — and **both A and B know it**. GCM **cannot tell A's messages apart from B's.**
>
> The **ECDSA signature is made with a private key only one vehicle owns.** *That* is what proves a specific message came from *Vehicle A specifically* — and gives **non-repudiation**: A cannot later deny having sent it.

| Mechanism | What it proves |
|---|---|
| AES-GCM auth tag | "This wasn't tampered with, and the sender knew the **shared** session key" |
| ECDSA signature | "This came from **Vehicle A specifically**, who cannot deny it" (authentication + non-repudiation) |

They are **not redundant** — they answer two different questions. That's why the project uses both.

---

## G. Replay & Freshness Protection

### G1. Why three layers — nonce cache + timestamp window + sequence numbers?

**What the code does:**
- `auth_protocol.py:ReplayCache` — remembers seen 256-bit nonces for 5 minutes (`config.py: REPLAY_WINDOW_SECONDS = 300`).
- `auth_protocol.py:TimestampValidator` — rejects anything older than 5 seconds (`config.py: TIMESTAMP_MAX_AGE = 5.0`).
- `v2v_protocol.py:secure_receive` — rejects a BSM whose `sequence_num` is not greater than the last one seen.

**Why all three — defence in depth.** Each single mechanism has a gap that the others close:

| Mechanism | Catches | Gap when used *alone* |
|---|---|---|
| **Timestamp window (5 s)** | Old captured messages replayed much later | A replay *within* the 5-second window slips through |
| **Nonce cache** | Any exact-duplicate message, even within the window | Cache would grow forever without the time-based expiry |
| **Sequence numbers** | Re-ordered, duplicated, or *suppressed* (dropped) messages | Resets on reconnect; doesn't carry a wall-clock time |

Together they cover replay *and* reordering *and* message suppression. No single one does.

**Why a 5-second timestamp window?** It's a deliberate trade-off: long enough to tolerate normal clock skew and network delay between two machines, short enough that the window an attacker can replay inside is tiny.

### G2. Why a **256-bit** handshake nonce but only a **96-bit** GCM nonce?

Different jobs, different sizes:
- **Handshake nonce — 256-bit** (`os.urandom(32)`): must be *globally collision-resistant* across the system's whole lifetime. 256 bits makes an accidental repeat astronomically impossible.
- **GCM nonce — 96-bit** (`os.urandom(12)`): only needs uniqueness *within one short session under one key*, and 96 bits is GCM's optimal native size (see B3).

---

## H. Supporting Engineering Choices

### H1. Why the PyCA `cryptography` library (not roll-your-own)?

**The #1 rule of applied cryptography: never invent your own.** The `cryptography` library is OpenSSL-backed, professionally audited, and exposes *misuse-resistant* high-level APIs (`AESGCM`, `HKDF`, `x509`). Alternatives: PyCryptodome (also fine, but `cryptography` has the de-facto-standard modern API and stronger X.509 support); `hashlib` + manual math (re-implementing primitives = guaranteed subtle bugs — rejected outright).

### H2. Why `os.urandom` and not Python's `random`?

`crypto.py` and `auth_protocol.py` use **`os.urandom`** for every key and nonce. Python's `random` module is a **Mersenne Twister** — fast but **predictable**: observe enough outputs and you can compute all future ones. Using it for a key or nonce would silently destroy all security. `os.urandom` is the OS **CSPRNG** (cryptographically secure).

> **Nice detail to point out:** `node/vehicle_node.py` *does* use `random` — but only to jitter the *simulated* speed/GPS values in fake BSMs. That data isn't security-sensitive, so it's a correct, deliberate split: CSPRNG for secrets, fast PRNG for simulation.

### H3. Why SHA-256 as the hash everywhere?

ECDSA, HKDF, and certificate signing all use **SHA-256**: ~128-bit collision resistance (matches our P-256 / AES strength — balanced design), fast, hardware-accelerated, universally supported. **SHA-1** is rejected (practical collisions exist since 2017). **SHA-512 / SHA-3** offer no benefit at this security level — SHA-512 is marginally slower for no gain, SHA-3 is less universally accelerated. Keep the whole system at one consistent ~128-bit level.

### H4. Why TCP + length-prefix framing (not UDP)?

**What the code does:** `node/vehicle_node.py` uses TCP sockets with `send_framed` / `recv_framed` — every message is prefixed with a 4-byte big-endian length.

- **Why framing:** TCP is a **byte stream** with no message boundaries. The 4-byte length prefix tells the receiver exactly how many bytes form one message. (A delimiter byte can't be used — encrypted/binary data can contain *any* byte, including the delimiter.)
- **Why TCP for this project:** The handshake is a strict ordered sequence; TCP's reliable, in-order delivery means we don't have to write packet-loss / retransmission logic. That keeps the focus on *security*, not networking.

> **Real-world contrast (important honesty point):** Actual V2V does **not** use TCP. It uses **connectionless UDP-style broadcast** over DSRC or C-V2X radio, because a car must shout BSMs to *all* nearby cars 10×/second with no time for connection setup. We chose TCP as a **deliberate teaching simplification** — say so in your presentation, and you turn a "limitation" into a sign you understand the real domain.

### H5. Why PEM format for storing certificates and keys?

`ca.py` / `issue_cert.py` write **PEM** (Base64 text with `-----BEGIN-----` headers) rather than raw binary **DER**. PEM is human-readable, survives copy-paste and email, and is the universal default for OpenSSL/X.509 tooling. DER (binary) is more compact but awkward to inspect or move around by hand.

---

## I. ⚠️ Deliberate Simplifications — What Real V2V Does Differently

Stating these *yourself* in the presentation is far stronger than being caught out by them. Each is a conscious teaching trade-off, not an oversight:

| Area | This project | Production V2V | Why we simplified |
|---|---|---|---|
| **Private key storage** | PEM files, **unencrypted** (`NoEncryption()`) | Encrypted keystore, **HSM / TPM** hardware | Lab clarity — no password/hardware setup. *Production must never store keys in plaintext.* |
| **Certificate revocation** | None | **CRLs / OCSP** — a stolen cert can be revoked | Out of scope; would need a revocation distribution system |
| **Privacy** | One fixed cert per vehicle (trackable) | **Rotating pseudonym certificates** | Stable IDs make the demo readable; real systems rotate certs to stop tracking |
| **Transport** | TCP, point-to-point, 1 peer (`listen(1)`) | UDP-style **broadcast** to all neighbours, DSRC/C-V2X radio | TCP reliability lets us focus on crypto |
| **Cert standard** | X.509 | **IEEE 1609.2** certificates | X.509 has better Python tooling for teaching |
| **The handshake** | Hand-written 4-step protocol | Vetted **TLS 1.3 / 1609.2** | Hand-rolling *teaches* the mechanics; you'd never deploy it |
| **Send rate** | 1 BSM/second | ~10 BSM/second | Slower rate keeps logs/dashboard human-readable |

**🎤 Closing talking point:** *"Every simplification here was a conscious choice to make the **security concepts** visible. The cryptography itself — P-256, ECDSA, ECDHE, AES-256-GCM, HKDF — is exactly what real systems use. What we simplified is the **deployment plumbing**, not the **security core**."*

---

## J. Quick-Fire Q&A — Rehearse These Before Your Presentation

| Likely question | Your one-line answer |
|---|---|
| *Why ECDSA, not RSA?* | Same 128-bit security, but ~8× smaller keys and faster — vital when verifying many messages/second. |
| *Why encrypt **and** sign?* | GCM's key is shared, so it can't identify *which* peer sent a message; only the ECDSA signature proves a specific sender (non-repudiation). |
| *What is forward secrecy?* | Ephemeral ECDH keys are discarded after each session, so stealing a long-term key later can't decrypt past traffic. |
| *Why HKDF — why not use the DH secret directly?* | The raw ECDH secret isn't uniformly random; HKDF turns it into a proper key and binds it to the session via the nonces. |
| *Why sign-then-encrypt?* | It ties the signature to the real content and stops attackers stripping/re-attaching signatures. |
| *How is replay stopped?* | Three layers: a 5-second timestamp window, a seen-nonce cache, and ever-increasing sequence numbers. |
| *Why a CA instead of shared keys?* | Each car trusts **one** CA cert and can then verify **any** car the CA signed — pre-shared keys would need n² secrets. |
| *Biggest weakness of this project?* | It's a single-machine TCP simplification with no revocation, plaintext key files, and a hand-rolled handshake — production would use 1609.2/TLS, an HSM, and CRLs. |
| *Why AES-256 over AES-128?* | 128 is already safe; 256 costs almost nothing extra and adds margin (including against future quantum attacks). |
| *What if a GCM nonce repeats?* | Catastrophic — it leaks the auth key and enables forgery; that's why every nonce comes fresh from `os.urandom`. |
