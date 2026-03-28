# Q — Quantum Cryptography and Post-Quantum Security

## Beginner Explanation
Quantum computers can solve certain mathematical problems exponentially faster than classical computers — including the math underlying most modern cryptography. A sufficiently powerful quantum computer could break RSA and ECC encryption. Post-quantum cryptography develops algorithms resistant to quantum attacks, ensuring security survives the quantum era.

## Technical Deep Dive

### The Quantum Threat to Current Cryptography
| Algorithm | Type | Quantum Threat | Timeline |
|-----------|------|---------------|---------|
| RSA-2048 | Asymmetric | Broken by Shor's algorithm | 10–20 years (estimate) |
| ECC-256 | Asymmetric | Broken by Shor's algorithm | 10–20 years |
| AES-256 | Symmetric | Weakened (Grover's algorithm halves effective key size) | Remains secure with AES-256 |
| SHA-256 | Hash | Weakened by Grover — effective 128-bit security | Remains secure |

### "Harvest Now, Decrypt Later" (HNDL)
Adversaries are collecting encrypted traffic today with the intent to decrypt it when quantum computers become available. Any long-lived secrets (classified data, private keys) encrypted today with RSA/ECC are at future risk.

### NIST Post-Quantum Standards (2024)
NIST finalized the first post-quantum cryptographic standards:

| Standard | Algorithm | Use Case |
|----------|-----------|---------|
| **FIPS 203** | ML-KEM (Kyber) | Key encapsulation / key exchange |
| **FIPS 204** | ML-DSA (Dilithium) | Digital signatures |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Digital signatures (hash-based) |

### Migration Planning
```
Phase 1 — Inventory (Now):
  - Catalog all cryptographic usage (TLS, SSH, code signing, database encryption)
  - Identify long-lived secrets at highest HNDL risk

Phase 2 — Hybrid Deployment (Near-term):
  - Deploy hybrid TLS: classical (ECDH) + post-quantum (ML-KEM) simultaneously
  - Both must be compromised to break security

Phase 3 — Full Migration (When Standards Mature):
  - Replace RSA/ECC with ML-KEM/ML-DSA
  - Update certificate infrastructure

Example: TLS 1.3 + X25519Kyber768 hybrid key exchange
```

### Quantum Key Distribution (QKD)
QKD uses quantum physics (photon polarization) to distribute keys with information-theoretic security — any eavesdropping disturbs the quantum states and is detected. Current limitation: requires dedicated fiber; impractical over long distances.

## Real-World Relevance
**NSA CNSS Advisory (2022):** The NSA directed all US National Security Systems to begin post-quantum migration planning immediately, citing the HNDL threat. Organizations handling government data face mandatory migration timelines.

## Defensive Measures
1. Inventory all cryptographic usage — know where RSA and ECC are in your systems
2. Prioritize migration of highest-sensitivity, longest-lived data first
3. Implement hybrid TLS in new deployments (classical + post-quantum)
4. Follow NIST PQC migration guidance (NIST SP 800-208)
5. Continue using AES-256 for symmetric encryption — it remains quantum-resistant

## Practice Challenge
1. List all places in a lab application that use RSA or ECC (TLS certificates, SSH keys, JWT signing).
2. Research the ML-KEM (Kyber) algorithm and describe in your own words how it differs from Diffie-Hellman.
3. Check if your OpenSSL version supports hybrid post-quantum key exchange: `openssl list -kem-algorithms`
