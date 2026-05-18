How CA works ?
CA (Certificate Authority) is the trusted signer that vouches for vehicle identities.
It issues X.509 certificates that bind a vehicle's public key to a name (e.g., "vehicle-a").

what is X.509 ?
X.509 is a standard format for digital certificates used in computer security.


Other vehicles trust the CA certificate; they verify peer certificates by checking the CA's signature.

ECDSA P-256 ?
ECDSA        +        P-256
(what it does)     (which math curve it uses)


Part 2: P-256 — The Curve
The "P-256" part specifies which elliptic curve to use for the math. 

Why not just use RSA?
RSA Key Size   : 3072 bits Security
ECC (P-256) Key Size : 128-bit security

But both give same amount of security.

ECC gives you the same security as RSA but with ~12x smaller keys. For V2V vehicles that broadcast 10 safety messages per second, smaller = faster = essential.

Part 3: ECDSA — The Signature Algorithm
ECDSA = Elliptic Curve Digital Signature Algorithm



What a PEM -- (Privacy Enhanced Mail) File Actually Looks Like
Binary uses 256 possible byte values (0–255). Some of these are invisible control characters that break text systems. Base64 converts every 3 bytes of binary into 4 safe printable characters — using only 64 safe characters:
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
a b c d e f g h i j k l m n o p q r s t u v w x y z
0 1 2 3 4 5 6 7 8 9 + /
These 64 characters are universally safe across every OS, email system, terminal, and protocol.

X.509 Certificate (structured data)
        ↓
    DER Encoding (raw binary — like a compiled file)
        ↓
    Base64 Encoding (binary → safe text characters)
        ↓
    Wrap with BEGIN/END headers
        ↓
    .pem file ✅ — safe to share anywhere

    Plain text can't carry binary safely. PEM is the "padded envelope" that makes binary data safe to travel across any system, email, or network.