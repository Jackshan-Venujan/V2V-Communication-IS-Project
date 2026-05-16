# V2V Communication Security Simulation

A secure **Vehicle-to-Vehicle (V2V)** communication system built with Python, demonstrating how two vehicles can exchange safety messages over an untrusted network while guaranteeing confidentiality, integrity, authentication, and non-repudiation.

---

## What Is This Project?

Imagine two cars driving on a highway. They need to warn each other about sudden braking, lane changes, or obstacles ahead — in real time. These safety messages are called **Basic Safety Messages (BSMs)** and are broadcast multiple times per second in real V2V systems.

**The problem:** The communication channel (radio waves / network) is **untrusted**. Anyone could:
- **Eavesdrop** on messages (read private data)
- **Tamper** with messages (change "speed: 60 km/h" to "speed: 0 km/h")
- **Impersonate** a vehicle (pretend to be Car A when you're actually a hacker)
- **Replay** old messages (re-send yesterday's "I'm braking!" to cause confusion today)

**Our solution:** This project builds a complete security layer that protects against all of these attacks using industry-standard cryptographic techniques.

---

## How Does It Work?

The system has three main stages: **Identity**, **Authentication**, and **Secure Messaging**.

### Stage 1: Identity — "Who Are You?" (Certificate Authority)

Before any communication begins, each vehicle needs a trusted digital identity — like a passport.

```
┌──────────────────────┐
│  Certificate Authority│  ← The "passport office"
│      (CA)             │
│                       │
│  Has a master key     │
│  that signs all certs │
└───────┬──────┬────────┘
        │      │
   Signs │      │ Signs
        ▼      ▼
  ┌──────────┐  ┌──────────┐
  │Vehicle A │  │Vehicle B │
  │ Cert     │  │ Cert     │  ← Digital "passports"
  │ + Key    │  │ + Key    │
  └──────────┘  └──────────┘
```

- The **CA** (`ca/ca.py`) generates a root key pair and a self-signed root certificate.
- Each vehicle gets a **certificate** signed by the CA (`ca/issue_cert.py`), proving its identity.
- Any vehicle can **verify** another vehicle's certificate by checking the CA's signature — if the CA didn't sign it, it's fake.

**Real-world analogy:** A passport office (CA) issues passports (certificates). When you show your passport at a border (to another vehicle), they verify it's genuine by checking the issuing authority's stamp (CA signature).

### Stage 2: Authentication — "Prove It!" (4-Step Handshake)

When two vehicles want to communicate, they run a **mutual authentication handshake** — both sides prove their identity to each other before exchanging any data.

```
Vehicle A (Initiator)                    Vehicle B (Responder)
      │                                         │
      │─── STEP 1: HELLO ──────────────────────►│
      │    "Hi! Here's my certificate           │
      │     and a random number (NonceA)"       │
      │                                         │
      │    Vehicle B checks:                    │
      │    ✓ Is A's cert signed by the CA?      │
      │    ✓ Is A's cert still valid?           │
      │    ✓ Is the timestamp fresh?            │
      │                                         │
      │◄── STEP 2: CHALLENGE ──────────────────│
      │    "Here's MY cert, MY random number    │
      │     (NonceB), and I signed both         │
      │     nonces with my private key"         │
      │                                         │
      │    Vehicle A checks:                    │
      │    ✓ Is B's cert signed by the CA?      │
      │    ✓ Does B's signature verify?         │
      │      (proves B has its private key)     │
      │                                         │
      │─── STEP 3: RESPONSE ──────────────────►│
      │    "I signed the nonces too, and        │
      │     here's my ECDH public key"          │
      │                                         │
      │    Vehicle B checks:                    │
      │    ✓ Does A's signature verify?         │
      │    ✓ Generate ECDH shared secret        │
      │                                         │
      │◄── STEP 4: ACK ───────────────────────│
      │    "Here's MY ECDH public key.          │
      │     Session established!"               │
      │                                         │
      │    Both compute the SAME session key    │
      │    using ECDH mathematics:              │
      │    A_priv × B_pub = B_priv × A_pub     │
      ▼                                         ▼
  ┌─────────────────────────────────────────────────┐
  │  Both vehicles now share a 256-bit session key  │
  │  that was NEVER sent over the network!          │
  └─────────────────────────────────────────────────┘
```

**Why 4 steps?** Each step serves a security purpose:
- Steps 1-2: Both sides show their "passport" (certificate verification)
- Steps 2-3: Both sides prove they own their private key (challenge-response)
- Steps 3-4: Both sides agree on a shared encryption key (ECDH key exchange)

**Forward secrecy:** The ECDH keys are **ephemeral** (generated fresh for each session). Even if someone steals a vehicle's long-term private key later, they cannot decrypt past conversations.

### Stage 3: Secure Messaging — "Sign, Then Encrypt" (BSM Exchange)

Once authenticated, vehicles exchange BSMs every second using a **Sign-then-Encrypt** pipeline:

```
SENDING A MESSAGE:
┌─────────┐    ┌──────────┐    ┌─────────────┐    ┌──────────────┐
│ BSM     │───►│ ECDSA    │───►│ AES-256-GCM │───►│ Send over    │
│ (plain) │    │ Sign     │    │ Encrypt     │    │ network      │
│         │    │ (stamp)  │    │ (seal)      │    │              │
└─────────┘    └──────────┘    └─────────────┘    └──────────────┘
    Speed=80        ✍️                🔒               📡
    Heading=45    Proves who        Hides content    Wire bytes
    Braking=No    wrote it          from attackers

RECEIVING A MESSAGE:
┌──────────────┐    ┌─────────────┐    ┌──────────┐    ┌─────────┐
│ Receive from │───►│ AES-256-GCM │───►│ ECDSA    │───►│ BSM     │
│ network      │    │ Decrypt     │    │ Verify   │    │ (plain) │
│              │    │ (unseal)    │    │ (check)  │    │         │
└──────────────┘    └─────────────┘    └──────────┘    └─────────┘
    📡                  🔓                 ✓✗             Speed=80
                   If tampered:       If forged:        Heading=45
                   REJECTED!          REJECTED!         Braking=No
```

**Why Sign-then-Encrypt (not Encrypt-then-Sign)?**
If we encrypted first and then signed, an attacker could strip the signature off one message and attach it to a different ciphertext. By signing the plaintext first, the signature is tied to the actual message content.

---

## Security Properties Achieved

| Property | What It Means | How We Achieve It |
|---|---|---|
| **Confidentiality** | Only the intended recipient can read the message | AES-256-GCM encryption with a session key |
| **Integrity** | Messages cannot be modified without detection | AES-GCM authentication tag (128-bit tamper seal) |
| **Authentication** | Both vehicles prove their identity to each other | X.509 certificates + 4-step handshake |
| **Non-repudiation** | A sender cannot deny sending a message | ECDSA digital signatures on every BSM |
| **Forward Secrecy** | Past sessions stay secure even if keys are leaked | Ephemeral ECDHE key exchange per session |
| **Replay Prevention** | Old messages cannot be re-used | Nonce cache + timestamp validation (5s window) |

---

## Threat Model — Attacks We Defend Against

### 1. Replay Attack
**What:** Attacker captures a valid BSM and re-sends it later.
**Defence:** Each BSM has a timestamp. Messages older than 5 seconds are rejected. Sequence numbers must always increase. Previously seen nonces are cached and rejected.
**Demo:** `python attacks\replay_attack.py`

### 2. Tamper Attack
**What:** Attacker intercepts a message and changes its content (e.g., modifying speed data).
**Defence:** AES-256-GCM produces a 128-bit authentication tag computed over the entire ciphertext. Changing even 1 bit causes the tag to mismatch, and decryption fails immediately.
**Demo:** `python attacks\tamper_attack.py`

### 3. Man-in-the-Middle (MITM) Attack
**What:** Attacker sits between two vehicles, intercepting and modifying their communication.
**Defence (Scenario A):** Attacker creates a fake certificate — rejected because it's not signed by the trusted CA. **Defence (Scenario B):** Attacker tries to forge a signature — rejected because they don't have the vehicle's private key.
**Demo:** `python attacks\mitm_attack.py`

---

## Cryptographic Algorithms Used

| Algorithm | Purpose | Why This Choice |
|---|---|---|
| **ECDSA P-256** | Digital signatures | 10x faster than RSA, smaller signatures (~71 bytes vs 256), 128-bit security level |
| **ECDH P-256** | Key exchange | Allows two parties to agree on a shared secret without ever transmitting it |
| **AES-256-GCM** | Authenticated encryption | Provides BOTH encryption and integrity in one operation; used in TLS 1.3 |
| **HKDF-SHA256** | Key derivation | Derives a strong session key from the ECDH shared secret + random nonces |
| **X.509 Certificates** | Identity binding | Industry-standard format (used in HTTPS/TLS); binds a public key to an identity |

---

## Project Structure

```
V2V-Communication-IS-Project/
│
├── ca/                              # Certificate Authority (PKI)
│   ├── ca.py                        #   Generate root CA key + self-signed certificate
│   ├── issue_cert.py                #   Issue X.509 certificates to vehicles
│   ├── verify_cert.py               #   Verify a certificate against the CA
│   └── certs/                       #   Generated PEM files (keys + certs)
│
├── crypto/
│   └── crypto.py                    # Core crypto: AES-GCM, ECDSA, ECDH, HKDF
│
├── protocol/
│   ├── auth_protocol.py             # 4-step mutual authentication handshake
│   └── v2v_protocol.py              # Sign-then-encrypt BSM protocol
│
├── node/
│   └── vehicle_node.py              # Main vehicle program (TCP server/client)
│
├── dashboard/
│   ├── app.py                       # Flask REST API for the dashboard
│   └── templates/
│       └── dashboard.html           # Real-time security monitoring UI
│
├── attacks/
│   ├── replay_attack.py             # Demonstrates replay attack (BLOCKED)
│   ├── tamper_attack.py             # Demonstrates tamper attack (BLOCKED)
│   └── mitm_attack.py               # Demonstrates MITM attack (BLOCKED)
│
├── tests/
│   └── evaluate_security.py         # Security benchmarks and evaluation report
│
├── config.py                        # Shared constants (ports, security params)
└── requirements.txt                 # Python dependencies
```

---

## How to Run

### Prerequisites

- Python 3.10 or later
- Windows (tested) or Linux/macOS

### 1. Install dependencies

```powershell
pip install cryptography flask requests pytest
```

### 2. Generate certificates

```powershell
python ca\ca.py
python ca\issue_cert.py --vehicle-id vehicle-a --output-dir ca\certs
python ca\issue_cert.py --vehicle-id vehicle-b --output-dir ca\certs
```

### 3. Start Vehicle A (Terminal 1)

```powershell
python node\vehicle_node.py `
  --vehicle-id vehicle-a `
  --port 9001 `
  --cert ca\certs\vehicle-a_cert.pem `
  --key ca\certs\vehicle-a_key.pem `
  --ca-cert ca\certs\ca_cert.pem `
  --dashboard-port 5001
```

### 4. Start Vehicle B (Terminal 2)

```powershell
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

### 5. Open dashboards in browser

- Vehicle A: http://localhost:5001
- Vehicle B: http://localhost:5002

### 6. Run attack demonstrations (Terminal 3)

```powershell
python attacks\replay_attack.py
python attacks\tamper_attack.py
python attacks\mitm_attack.py
```

### 7. Run security evaluation

```powershell
python tests\evaluate_security.py
```

---

## Two-Laptop Deployment

To demonstrate real cross-machine communication:

### Network Architecture

```
Laptop A (e.g. 192.168.1.100)          Laptop B (e.g. 192.168.1.101)
  Vehicle A :9001         <── TCP ──>     Vehicle B :9002
  Dashboard :5001                         Dashboard :5002
```

### Step 1: Find each laptop's IP

```powershell
ipconfig
```
Look for the IPv4 address under your WiFi adapter.

### Step 2: Open firewall ports (run as Administrator on BOTH laptops)

```powershell
netsh advfirewall firewall add rule name="V2V-9001" dir=in action=allow protocol=TCP localport=9001
netsh advfirewall firewall add rule name="V2V-9002" dir=in action=allow protocol=TCP localport=9002
netsh advfirewall firewall add rule name="V2V-5001" dir=in action=allow protocol=TCP localport=5001
netsh advfirewall firewall add rule name="V2V-5002" dir=in action=allow protocol=TCP localport=5002
```

### Step 3: Copy the project and certificates to Laptop B

Copy the entire project folder to Laptop B (USB or network share). Both laptops need all cert files in `ca/certs/`.

### Step 4: Start vehicles

**Laptop A** — runs Vehicle A as server (same command as single-machine).

**Laptop B** — connects to Laptop A (replace IP with Laptop A's actual address):
```powershell
python node\vehicle_node.py `
  --vehicle-id vehicle-b --port 9002 `
  --cert ca\certs\vehicle-b_cert.pem `
  --key ca\certs\vehicle-b_key.pem `
  --ca-cert ca\certs\ca_cert.pem `
  --peer-host 192.168.1.100 --peer-port 9001 `
  --dashboard-port 5002
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: No module named 'cryptography'` | Run `pip install cryptography flask requests pytest` |
| `Address already in use` on port 9001 | `netstat -ano \| findstr :9001` then `taskkill /PID <pid> /F` |
| Windows Firewall blocks connection | Click "Allow access" when prompted, or add rules above |
| Connection refused on two laptops | Verify both are on the same WiFi network and firewall rules are added |
| PowerShell line continuation | Use backtick `` ` `` at end of line (not `\` like Linux) |
