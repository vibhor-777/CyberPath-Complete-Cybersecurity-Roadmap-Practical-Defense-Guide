# J — JWT Security

## Beginner Explanation
JSON Web Tokens (JWTs) are a compact way to securely transmit information between parties as a JSON object. Think of a JWT like a tamper-evident sealed envelope — anyone can read what's on the outside, but if someone tampers with the contents, the seal breaks and the recipient knows.

## Technical Deep Dive
### JWT Structure
```
Header.Payload.Signature
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
     ↑                        ↑                                          ↑
  Base64({"alg":"HS256"})  Base64({"sub":"user123","role":"user"})   HMAC-SHA256 signature
```

### Common JWT Vulnerabilities

**Algorithm Confusion (alg:none attack):**
```
Attacker changes header: {"alg":"none"}
Removes signature entirely
Server accepts unsigned token if it trusts client's alg choice
```
**Fix:** Never accept `alg:none`. Explicitly specify allowed algorithms server-side.

**HS256 vs RS256 Confusion:**
Attacker with an RS256 public key signs a token with HS256 (using the public key as the HMAC secret), tricks server expecting RS256 into verifying with its public key.
**Fix:** Enforce algorithm on the server; never trust the header's `alg` value.

**Weak Secret Keys:**
HS256 tokens signed with weak secrets can be brute-forced offline.
**Fix:** Use cryptographically random secrets of at least 256 bits.

### Secure JWT Implementation
```python
import jwt
import os

SECRET = os.environ.get("JWT_SECRET")  # Never hardcode
ALGORITHM = "HS256"  # Or RS256 for asymmetric

# Sign
token = jwt.encode({"sub": "user123", "role": "user", "exp": expiry}, SECRET, algorithm=ALGORITHM)

# Verify — explicitly specify algorithm to prevent confusion attacks
try:
    payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])  # Note: list, not string
except jwt.ExpiredSignatureError:
    # Handle expired token
    pass
except jwt.InvalidTokenError:
    # Reject invalid token
    pass
```

## Real-World Relevance
In 2015, multiple APIs were found vulnerable to the `alg:none` attack, allowing complete authentication bypass. An attacker could modify their JWT payload (e.g., change `"role":"user"` to `"role":"admin"`) and access administrative endpoints.

## Defensive Measures
1. Always validate the `alg` claim server-side against an allowlist
2. Use short expiry times (`exp` claim) — 15 minutes for access tokens
3. Implement token revocation (blacklist or short-lived tokens with refresh)
4. Store JWTs in httpOnly cookies, not localStorage (prevents XSS theft)
5. Use RS256/ES256 (asymmetric) for distributed systems

## Practice Challenge
1. Decode a JWT at jwt.io (use a test token, never production).
2. Identify the header, payload, and signature components.
3. Try to modify the payload and observe what happens to the signature.
4. Write a Python script that generates and validates a HS256 JWT.
