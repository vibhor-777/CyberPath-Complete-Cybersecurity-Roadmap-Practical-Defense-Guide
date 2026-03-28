# C — Cryptography

## Beginner Explanation
Cryptography is the science of secure communication. Think of it as a secret language only you and your intended recipient understand. Encryption transforms readable data (plaintext) into unreadable ciphertext; decryption reverses the process. Without cryptography, every password, credit card number, and private message sent over the internet would be readable by anyone on the network.

## Technical Deep Dive

### Symmetric Encryption
Same key encrypts and decrypts. Fast; ideal for bulk data.

| Algorithm | Key Size | Status |
|-----------|---------|--------|
| AES-128/256 | 128/256-bit | ✅ Current standard |
| 3DES | 112-bit effective | ⚠️ Legacy; avoid |
| DES | 56-bit | ❌ Broken — never use |
| RC4 | Variable | ❌ Broken — never use |

```python
# AES-256-GCM encryption example (Python cryptography library)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = os.urandom(32)        # 256-bit key
nonce = os.urandom(12)      # 96-bit nonce (never reuse with same key!)
plaintext = b"Sensitive data"
aad = b"authenticated but not encrypted header"

aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
```

### Asymmetric Encryption
Key pair: public key encrypts, private key decrypts. Slower; used for key exchange and signatures.

| Algorithm | Key Size | Use Case |
|-----------|---------|---------|
| RSA-2048+ | 2048–4096 bit | Key exchange, signatures |
| ECC/ECDSA | 256–384 bit | Signatures, TLS |
| X25519 | 255 bit | Key agreement (Diffie-Hellman) |
| Ed25519 | 255 bit | Digital signatures (SSH keys) |

### Hashing
One-way transformation; cannot be reversed. Used for integrity verification and password storage.

| Algorithm | Output | Status |
|-----------|--------|--------|
| SHA-256 | 256-bit | ✅ Current standard |
| SHA-512 | 512-bit | ✅ Strong |
| SHA-3 | Variable | ✅ Alternative |
| MD5 | 128-bit | ❌ Broken for security |
| SHA-1 | 160-bit | ❌ Deprecated |

### Salting Passwords
A **salt** is a unique random value prepended to a password before hashing, preventing rainbow table attacks:
```
Without salt: SHA-256("password123") = same hash for all users with "password123"
With salt:    SHA-256("a3f9...password123") = unique hash per user
```
Use **bcrypt**, **scrypt**, or **Argon2** for password hashing — these are designed to be slow and defeat brute-force attacks.

### TLS/SSL — Transport Layer Security
TLS (the replacement for SSL) protects data in transit. The handshake:
```
1. Client Hello: Supported cipher suites, TLS version, random nonce
2. Server Hello: Chosen cipher suite, certificate
3. Key Exchange: ECDHE (Ephemeral Diffie-Hellman) — establishes session key
4. Finished: Both sides confirm handshake
5. Encrypted application data flows
```
**Perfect Forward Secrecy (PFS):** Using ephemeral keys (ECDHE) means even if the server's private key is later compromised, past sessions cannot be decrypted.

## Real-World Relevance
**The Adobe Breach (2013):** Adobe stored 153 million passwords using 3DES encryption with the same key for all users, and without salting. Because identical passwords produced identical ciphertexts, attackers could cross-reference entries to crack passwords in bulk. Proper bcrypt with unique salts would have made this vastly harder.

## Defensive Measures
1. Never implement your own cryptography — use vetted libraries (OpenSSL, libsodium, Python `cryptography`)
2. Use AES-256-GCM for symmetric encryption (provides both confidentiality AND integrity)
3. Use bcrypt/Argon2 for password hashing (not SHA-256)
4. Enforce TLS 1.2+ and disable TLS 1.0/1.1 and SSL
5. Enable Perfect Forward Secrecy (ECDHE cipher suites)
6. Rotate cryptographic keys regularly and store them in a secrets manager

## Practice Challenge
1. Using Python's `hashlib`, hash the string "password123" with SHA-256.
2. Now hash it again with a random salt prepended.
3. Verify that the same password with different salts produces different hashes.
4. Install `bcrypt` (`pip install bcrypt`) and hash the same password with bcrypt.
5. Time the difference — why is bcrypt's slowness a security feature?
