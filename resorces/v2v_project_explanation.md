# V2V Communication Security Project — Complete A-Z Explanation

## Project Overview

This project simulates **secure Vehicle-to-Vehicle (V2V) communication**. Two vehicles (running as Python programs) exchange **Basic Safety Messages (BSMs)** — containing speed, heading, braking, GPS — over a TCP network. The entire communication is protected by a layered cryptographic security system.

**The core problem:** V2V messages travel over an untrusted wireless channel. Without security, an attacker could eavesdrop, tamper, impersonate, or replay messages — potentially causing real accidents.

**The solution:** Three security stages that mirror how real-world secure communication works (similar to TLS/HTTPS):

```
STAGE 1: IDENTIFICATION     →  "Who are you?" (Certificates)
STAGE 2: KEY SHARING         →  "Let's agree on a secret key" (ECDH Handshake)  
STAGE 3: SECURE MESSAGING    →  "Now let's talk securely" (Sign-then-Encrypt)
```

---

## STAGE 1: IDENTIFICATION (Certificate Part)

### What Happens

Before any vehicle can communicate, it needs a **digital identity** — like a digital passport. This is handled by a **Certificate Authority (CA)**.

### Step-by-Step Flow

```
1. Run ca/ca.py         → Creates the CA (the "passport office")
2. Run ca/issue_cert.py → Issues a certificate to each vehicle
3. ca/verify_cert.py    → Can verify any certificate is genuine
```

### How It Works Internally

#### Step 1: CA Setup ([ca/ca.py](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/ca/ca.py))

1. **Generate CA Key Pair**: Creates an ECDSA private key on the **NIST P-256 curve** (`generate_private_key(SECP256R1())`)
2. **Create Self-Signed Root Certificate**: An X.509 certificate where subject = issuer (signs itself)
   - Subject: `CN=V2V-Root-CA, O=V2V-Security-Lab`
   - Validity: 10 years
   - Extensions: `BasicConstraints(ca=True)` — marks this as a CA certificate
   - `KeyUsage(key_cert_sign=True)` — only allowed to sign other certificates
   - Signed with SHA-256
3. **Save to disk**: `ca/certs/ca_cert.pem` (public, shared with everyone) and `ca/certs/ca_key.pem` (SECRET, never shared)

#### Step 2: Vehicle Certificate Issuance ([ca/issue_cert.py](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/ca/issue_cert.py))

For each vehicle (e.g., `vehicle-a`):
1. **Generate Vehicle Key Pair**: Fresh ECDSA P-256 key pair for the vehicle
2. **Build Certificate**:
   - Subject: `CN=vehicle-a, O=V2V-Security-Lab`
   - Issuer: The CA's subject name (`V2V-Root-CA`)
   - Contains the vehicle's **public key**
   - `BasicConstraints(ca=False)` — this is NOT a CA
   - `KeyUsage(digital_signature=True)` — can only create signatures
   - Validity: 1 year
3. **Sign with CA's private key**: `builder.sign(private_key=ca_key, algorithm=SHA256())`
4. **Save**: `vehicle-a_cert.pem` + `vehicle-a_key.pem`

#### Step 3: Certificate Verification ([ca/verify_cert.py](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/ca/verify_cert.py))

Three checks performed:
1. **Signature Check**: Uses the CA's public key to verify the signature on the vehicle certificate (`ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, ECDSA(SHA256()))`)
2. **Date Check**: Is the certificate within its validity window (not expired, not too early)?
3. **Subject Check**: Does the certificate have a valid subject name?

### Technique: X.509 Certificates with ECDSA P-256

**What is X.509?** The international standard format for digital certificates (RFC 5280). It's the same format used in HTTPS/TLS everywhere on the internet. A certificate **binds a public key to an identity**.

**What is ECDSA P-256?** Elliptic Curve Digital Signature Algorithm on the NIST P-256 curve (also called secp256r1). It provides **128-bit security level**.

### Why ECDSA P-256? Why NOT Other Alternatives?

| Alternative | Why We Didn't Choose It |
|---|---|
| **RSA-2048** | Key size: 256 bytes vs ECDSA's 32 bytes. Signatures: 256 bytes vs ~71 bytes. RSA is **10x slower** for signing. In V2V, vehicles broadcast 10 BSMs/second — RSA's overhead is unacceptable for real-time constraints. |
| **RSA-4096** | Even slower and larger than RSA-2048. Completely impractical for bandwidth-constrained V2V. |
| **EdDSA (Ed25519)** | Faster than ECDSA but uses Curve25519 which is **not NIST-approved**. V2V standards (IEEE 1609.2, SAE J2735) specifically mandate NIST curves. SCMS (Security Credential Management System) uses P-256. |
| **ECDSA P-384/P-521** | Overkill for V2V. P-256 gives 128-bit security which is sufficient. P-384/521 are slower with larger keys/signatures for no practical benefit in this context. |
| **Pre-shared keys (no PKI)** | Doesn't scale. With 1000 vehicles, you'd need 499,500 unique key pairs. Certificates let any vehicle verify any other vehicle with just the CA's public key. |

> **V2V-specific reason:** The IEEE 1609.2 standard for V2V security **explicitly specifies ECDSA with P-256**. Using P-256 means our simulation aligns with the real-world V2V security standard (SCMS).

---

## STAGE 2: KEY SHARING (4-Step Mutual Authentication Handshake)

### What Happens

When two vehicles want to communicate, they run a **4-step mutual authentication handshake**. This achieves THREE things simultaneously:
1. Both vehicles **prove their identity** (mutual authentication)
2. Both vehicles **prove they own their private key** (challenge-response)
3. Both vehicles **agree on a shared session key** (ECDH key exchange)

### The 4 Steps in Detail

**Code:** [auth_protocol.py](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/protocol/auth_protocol.py)

#### Step 1: HELLO (Initiator → Responder)

```python
# Vehicle A builds and sends:
HelloMessage {
    vehicle_id:       "vehicle-a"
    certificate_pem:  <Vehicle A's X.509 certificate>
    nonce:            <32 random bytes as hex>    # 256-bit random challenge
    timestamp:        <current Unix time>
}
```

**What's a nonce?** A "number used once" — 32 random bytes (256 bits). It serves two purposes:
- **Freshness**: Proves this message was just created (not replayed)
- **Challenge**: The other side must sign this to prove identity

#### Step 2: CHALLENGE (Responder → Initiator)

Vehicle B receives the HELLO and performs THREE checks:
1. **Timestamp validation**: Is the message less than 5 seconds old? (`TimestampValidator`)
2. **Replay check**: Has this nonce been seen before? (`ReplayCache`)
3. **Certificate verification**: Is A's certificate signed by our trusted CA? (`verify_certificate_against_ca()`)

Then Vehicle B responds:
```python
ChallengeMessage {
    vehicle_id:       "vehicle-b"
    certificate_pem:  <Vehicle B's X.509 certificate>
    nonce:            <32 random bytes — Vehicle B's nonce>
    signed_nonces:    ECDSA_Sign(B_private_key, NonceA + NonceB)
    timestamp:        <current Unix time>
}
```

**Key insight:** By signing `NonceA + NonceB`, Vehicle B proves it possesses its private key (only the holder of B's private key can create a valid signature that matches B's public key in the certificate).

#### Step 3: RESPONSE (Initiator → Responder)

Vehicle A receives the CHALLENGE and:
1. Validates timestamp and replay
2. Verifies B's certificate against the CA
3. **Verifies B's signature**: `ecdsa_verify(B_public_key, NonceA+NonceB, signature)` — if this passes, B is authentic
4. **Generates ephemeral ECDH key pair**: `generate_ecdh_keypair()` — a FRESH key pair for THIS session only

```python
ResponseMessage {
    signed_nonces:       ECDSA_Sign(A_private_key, NonceA + NonceB)
    ecdh_public_key_pem: <A's ephemeral ECDH public key>
    timestamp:           <current Unix time>
}
```

#### Step 4: ACK (Responder → Initiator)

Vehicle B receives the RESPONSE and:
1. **Verifies A's signature** — now BOTH sides have proven their identity
2. **Generates its own ECDH key pair**
3. **Computes shared secret**: `ecdh_shared_secret(B_ecdh_private, A_ecdh_public)` — the ECDH math magic
4. **Derives session key**: `HKDF-SHA256(shared_secret, salt=NonceA+NonceB, info="v2v-session-key-v1")` → 32-byte AES-256 key

```python
AckMessage {
    ecdh_public_key_pem: <B's ephemeral ECDH public key>
    session_established: true
}
```

Vehicle A receives the ACK, computes the SAME shared secret using its ECDH private key + B's ECDH public key, and derives the SAME session key.

**The magic of ECDH:** `A_private × B_public = B_private × A_public` → identical shared secret, but the secret was **NEVER transmitted** over the network!

### Technique: ECDH (Elliptic Curve Diffie-Hellman) on P-256

ECDH lets two parties agree on a shared secret by only exchanging public keys.

**Math (simplified):**
- A generates: private `a`, public `A = a × G` (G is the curve generator point)
- B generates: private `b`, public `B = b × G`
- A computes: `a × B = a × b × G`
- B computes: `b × A = b × a × G`
- Both get the same point: `a × b × G` — this is the shared secret

An eavesdropper sees `A` and `B` but cannot compute `a × b × G` without knowing `a` or `b`. This is the **Elliptic Curve Discrete Logarithm Problem (ECDLP)** — computationally infeasible.

### Technique: HKDF-SHA256 (Key Derivation)

The raw ECDH output is not directly suitable as an encryption key. HKDF (HMAC-based Key Derivation Function) stretches and randomizes it:
```python
HKDF(algorithm=SHA256, length=32, salt=NonceA+NonceB, info=b"v2v-session-key-v1")
```
- **Salt** = `NonceA + NonceB`: Ensures different sessions produce different keys even with the same ECDH secret
- **Info** = `"v2v-session-key-v1"`: Domain separation string
- **Output**: 32 bytes = 256-bit AES key

### Technique: Ephemeral Keys (Forward Secrecy)

The ECDH keys are **ephemeral** — generated fresh for EACH session and then discarded. This provides **Perfect Forward Secrecy (PFS)**: even if a vehicle's long-term private key is compromised in the future, past session keys cannot be recovered because the ephemeral keys no longer exist.

### Why These Techniques? Why NOT Alternatives?

| Alternative | Why We Didn't Choose It |
|---|---|
| **RSA Key Exchange** | The client picks a random key, encrypts with server's RSA public key, sends it. Problem: NO forward secrecy — if the RSA key is later compromised, ALL past sessions can be decrypted. |
| **Static DH (non-ephemeral)** | Same key pair every session → no forward secrecy. If the static DH key leaks, all past and future sessions are compromised. |
| **Pre-shared Key (PSK)** | Requires securely distributing keys to every vehicle pair beforehand. With N vehicles you need N×(N-1)/2 keys. Completely unscalable for V2V networks with thousands of vehicles. |
| **Plain Diffie-Hellman (non-EC)** | Requires 2048-bit or 3072-bit keys for 128-bit security. ECDH achieves the same with 256-bit keys — **10x smaller**, critical for V2V's bandwidth constraints. |
| **X25519 (Curve25519)** | Faster than P-256 ECDH, but not NIST-approved and not specified in IEEE 1609.2. For V2V standards compliance, P-256 is required. |
| **Simple nonce exchange (no HKDF)** | Raw ECDH output has uneven bit distribution. HKDF ensures the derived key has proper randomness properties suitable for AES. Without it, subtle cryptographic weaknesses could exist. |

> **V2V-specific reason:** Ephemeral ECDH is critical for V2V because vehicles are long-lived assets (10+ years). If a car's key is compromised in year 5, forward secrecy ensures all BSMs from years 1-4 remain confidential.

### Replay & Freshness Protection

Two mechanisms work together during the handshake:

1. **`ReplayCache`** ([auth_protocol.py:158-186](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/protocol/auth_protocol.py#L158-L186)): Stores nonce hashes for 5 minutes. If the same nonce appears twice → replay attack detected → REJECT.

2. **`TimestampValidator`** ([auth_protocol.py:189-208](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/protocol/auth_protocol.py#L189-L208)): Messages older than 5 seconds are rejected. Prevents replaying captured handshake messages.

---

## STAGE 3: MESSAGE ENCRYPTION AND SENDING

### What Happens

After the handshake, both vehicles share an identical 32-byte AES-256 session key. They now exchange encrypted BSMs every second using a **Sign-then-Encrypt** pipeline.

**Code:** [v2v_protocol.py](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/protocol/v2v_protocol.py)

### The BSM (Basic Safety Message)

Inspired by SAE J2735 standard:
```python
BasicSafetyMessage {
    vehicle_id:    "vehicle-a"
    speed_kmh:     80.5
    heading_deg:   45.0       # 0=North, 90=East
    latitude:      6.9271
    longitude:     79.8612
    timestamp:     1747489200.123
    sequence_num:  42
    brake_applied: False
    acceleration:  1.2
}
```

### Sending Pipeline (Sign-then-Encrypt)

**Function:** `secure_send()` in [v2v_protocol.py:240-288](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/protocol/v2v_protocol.py#L240-L288)

```
Step 1: BSM → JSON bytes
Step 2: ECDSA Sign the plaintext bytes → signature (~71 bytes)
Step 3: Combine: [4-byte BSM length][BSM bytes][signature bytes]
Step 4: AES-256-GCM Encrypt the combined payload → ciphertext + nonce + auth_tag
Step 5: Wrap in SecureBSM → binary wire format
```

**Wire format of SecureBSM:**
```
[sender_id_len:2 bytes][sender_id][sequence:4 bytes][nonce:12 bytes][auth_tag:16 bytes][ct_len:4 bytes][ciphertext]
```

### Receiving Pipeline (Decrypt-then-Verify)

**Function:** `secure_receive()` in [v2v_protocol.py:291-375](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/protocol/v2v_protocol.py#L291-L375)

```
Step 1: Parse SecureBSM from raw bytes
Step 2: AES-GCM Decrypt (if tampered → auth tag mismatch → TamperError)
Step 3: Unpack plaintext → BSM bytes + signature
Step 4: ECDSA Verify signature (if forged → SignatureError → TamperError)
Step 5: Parse BSM, check sequence number (must increase), check timestamp (<5s old)
```

### Technique: AES-256-GCM (Authenticated Encryption)

AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** cipher. It provides BOTH:
- **Confidentiality**: Encrypts the data (AES in Counter mode)
- **Integrity**: Produces a 128-bit authentication tag (GMAC) computed over the ciphertext

**Parameters used:**
- Key: 32 bytes (256-bit) — from the ECDH-derived session key
- Nonce: 12 bytes (96-bit) — randomly generated per message (`os.urandom(12)`)
- Auth tag: 16 bytes (128-bit) — tamper-detection seal

**How tamper detection works:** The auth tag is a cryptographic checksum of the entire ciphertext. If even ONE BIT of the ciphertext is changed, the recomputed tag won't match → decryption function raises `InvalidTag` → message rejected.

### Technique: ECDSA Signatures on BSMs

Every BSM is signed with the sender's long-term ECDSA private key BEFORE encryption:
```python
signature = private_key.sign(bsm_bytes, ECDSA(SHA256()))
```

This provides:
- **Authentication**: Only the holder of vehicle-a's private key can produce a valid signature
- **Non-repudiation**: The sender cannot deny they sent the message (the signature is mathematical proof)

### Why Sign-then-Encrypt? Why NOT Encrypt-then-Sign?

**Sign-then-Encrypt** (what we use):
1. Sign the plaintext BSM
2. Encrypt (BSM + signature) together

**Encrypt-then-Sign** (what we rejected):
1. Encrypt the BSM
2. Sign the ciphertext

**Problem with Encrypt-then-Sign:** An attacker could strip the signature off one ciphertext and attach it to a DIFFERENT ciphertext. The signature would verify (it was validly created), but it's attached to the wrong message. With Sign-then-Encrypt, the signature is bound to the plaintext content inside the encryption — it can't be separated.

### Why These Techniques? Why NOT Alternatives?

| Alternative | Why We Didn't Choose It |
|---|---|
| **AES-CBC + HMAC-SHA256** | Two separate operations (encrypt + MAC). More complex, more room for implementation errors (e.g., Padding Oracle attacks on CBC). AES-GCM does both in one atomic operation — simpler and faster. |
| **AES-ECB** | No integrity protection at all. Same plaintext block always produces same ciphertext (pattern leakage). Completely insecure for V2V. |
| **AES-CTR (without authentication)** | Provides confidentiality but NO integrity. An attacker could flip bits in the ciphertext and the receiver wouldn't know. Useless for V2V where message integrity is life-critical. |
| **ChaCha20-Poly1305** | Excellent AEAD cipher (used in TLS 1.3). However, AES-GCM is **hardware-accelerated** on modern CPUs via AES-NI instructions. V2V ECUs (Electronic Control Units) typically have AES hardware support, making AES-GCM faster in practice. |
| **3DES** | Only 112-bit effective security, 3x slower than AES. Deprecated by NIST. |
| **No encryption (only signing)** | BSMs would be readable by anyone. Exposes vehicle location, speed, and movement patterns — massive privacy violation. V2V privacy regulations require encryption. |

> **V2V-specific reason:** AES-256-GCM is the cipher used in TLS 1.3 and is specified in IEEE 1609.2 for V2V security. It's hardware-accelerated on automotive ECUs, which is critical when processing 10+ BSMs per second from multiple vehicles.

---

## SECURITY PROPERTIES ACHIEVED (CIA Triad + More)

| Property | Mechanism | Code Location |
|---|---|---|
| **Confidentiality** | AES-256-GCM encryption | `crypto.py:aes_gcm_encrypt()` |
| **Integrity** | AES-GCM 128-bit auth tag | `crypto.py:aes_gcm_decrypt()` |
| **Authentication** | X.509 certs + 4-step handshake | `auth_protocol.py` |
| **Non-repudiation** | ECDSA signature on every BSM | `v2v_protocol.py:secure_send()` |
| **Forward Secrecy** | Ephemeral ECDH keys per session | `crypto.py:generate_ecdh_keypair()` |
| **Replay Prevention** | Nonce cache + timestamps + sequence numbers | `ReplayCache` + `TimestampValidator` |

---

## ATTACK DEMONSTRATIONS

### 1. Replay Attack ([replay_attack.py](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/attacks/replay_attack.py))

**Attack:** Capture a valid BSM, wait 6 seconds, replay the exact bytes.
**Defence:** `TimestampValidator` rejects messages older than 5 seconds. `SequenceError` catches out-of-order sequence numbers.

### 2. Tamper Attack ([tamper_attack.py](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/attacks/tamper_attack.py))

**Attack:** Intercept encrypted BSM, flip 3 bytes in the ciphertext.
**Defence:** AES-GCM auth tag no longer matches → `InvalidTag` → `TamperError`. Even 1 flipped bit causes rejection.

### 3. MITM Attack ([mitm_attack.py](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/attacks/mitm_attack.py))

**Scenario A — Fake Certificate:** Attacker creates a self-signed cert pretending to be vehicle-a. Defence: CA signature verification fails because the cert wasn't signed by the trusted CA.

**Scenario B — Forged Signature:** Attacker signs nonces with their own key (not vehicle-a's). Defence: ECDSA verification with vehicle-a's public key fails because the attacker doesn't have vehicle-a's private key.

---

## COMPLETE DATA FLOW (End-to-End)

```
┌─ SETUP (one-time) ──────────────────────────────────┐
│ 1. ca.py          → CA key pair + root certificate   │
│ 2. issue_cert.py  → Vehicle A cert + key             │
│ 3. issue_cert.py  → Vehicle B cert + key             │
└──────────────────────────────────────────────────────┘

┌─ HANDSHAKE (per session) ────────────────────────────┐
│ 4. A→B: HELLO     {CertA, NonceA, timestamp}        │
│ 5. B→A: CHALLENGE {CertB, NonceB, Sign_B(NA+NB)}    │
│ 6. A→B: RESPONSE  {Sign_A(NA+NB), ECDH_PubA}        │
│ 7. B→A: ACK       {ECDH_PubB}                       │
│    → Both derive: SessionKey = HKDF(ECDH_secret)     │
└──────────────────────────────────────────────────────┘

┌─ MESSAGING (continuous, every 1 second) ─────────────┐
│ 8. BSM → ECDSA Sign → AES-GCM Encrypt → TCP Send    │
│ 9. TCP Recv → AES-GCM Decrypt → ECDSA Verify → BSM  │
│    + Timestamp check + Sequence check + Replay check │
└──────────────────────────────────────────────────────┘
```

---

## NETWORKING LAYER

**Code:** [vehicle_node.py](file:///c:/Users/Kavindu/Desktop/SEM7/IS/project/V2V-Communication-IS-Project/node/vehicle_node.py)

- Uses **TCP sockets** with length-prefixed framing (`send_framed` / `recv_framed`)
- Vehicle A runs as **server** (listens on port 9001)
- Vehicle B runs as **client** (connects to A's IP:9001)
- After handshake, two threads run: one for sending BSMs, one for receiving
- A **Flask dashboard** runs on a separate port (5001/5002) showing real-time security status

---

## SUMMARY TABLE: All Algorithms & Why

| Algorithm | Used For | V2V-Specific Justification |
|---|---|---|
| **ECDSA P-256** | Digital signatures (certs + BSMs) | Mandated by IEEE 1609.2. Small signatures (~71 bytes) fit in V2V's 300-byte BSM limit. 10x faster than RSA. |
| **ECDH P-256 (Ephemeral)** | Key exchange | Forward secrecy for long-lived vehicles. Key never transmitted. Same curve as signatures (reuse hardware). |
| **AES-256-GCM** | Authenticated encryption | Hardware-accelerated on automotive ECUs. One operation for encrypt+integrity. Used in TLS 1.3. |
| **HKDF-SHA256** | Key derivation | Turns raw ECDH output into proper AES key. Salt includes both nonces for uniqueness. |
| **X.509 Certificates** | Identity binding | Industry standard. Scales with PKI — any vehicle verifies any other with just the CA cert. |
| **SHA-256** | Hashing (inside ECDSA, HKDF) | 128-bit collision resistance. NIST standard. Fast in software and hardware. |
