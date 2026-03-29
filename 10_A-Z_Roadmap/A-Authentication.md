# A — Authentication

## Beginner Explanation
Authentication is the process of proving you are who you claim to be. Think of it as showing your ID at a nightclub door — the bouncer verifies your identity before allowing entry. In computing, systems verify your identity before granting access to resources.

## Technical Deep Dive

### Authentication Factors
| Factor Type | What it is | Examples |
|-------------|-----------|---------|
| **Something you know** | Knowledge-based | Password, PIN, security question |
| **Something you have** | Possession-based | Hardware token (YubiKey), authenticator app, smart card |
| **Something you are** | Inherence/biometric | Fingerprint, face recognition, iris scan |

**Multi-Factor Authentication (MFA)** requires two or more factors — combining something you know with something you have dramatically reduces account takeover risk.

### Password Authentication
Passwords are stored as salted hashes, never plaintext:
```
User enters: "P@ssw0rd123"
System computes: SHA-256(salt + "P@ssw0rd123") = hash
Stored in DB: {salt: "a3f9...", hash: "8b2c..."}
```

### Kerberos Authentication (Active Directory)
```
1. Client → KDC (AS): "I am user Alice" + timestamp encrypted with Alice's key
2. KDC → Client (AS-REP): TGT (Ticket Granting Ticket) encrypted with KDC secret
3. Client → KDC (TGS): TGT + "I want access to File Server"
4. KDC → Client (TGS-REP): Service Ticket for File Server
5. Client → File Server: Service Ticket
6. File Server: Decrypts ticket, verifies, grants access
```

**NTLM Relay Attack Risk:** NTLM (older protocol) is vulnerable to relay attacks where an attacker intercepts authentication and forwards it to gain access. Mitigation: Disable NTLM where possible, enable SMB signing, deploy EPA (Extended Protection for Authentication).

### Modern Authentication: OAuth 2.0 and OIDC
OAuth 2.0 is an authorization framework; OpenID Connect (OIDC) adds authentication on top:
- **Authorization Code + PKCE:** Most secure flow for web and mobile apps
- **Client Credentials:** Machine-to-machine (no user involved)
- Never use Implicit flow (deprecated)

## Real-World Relevance
The **2020 Twitter Bitcoin Scam** was enabled by social engineering attackers to convince Twitter employees to provide access to internal tools, bypassing authentication entirely. 130 high-profile accounts were compromised. Even strong technical authentication can be undermined by social engineering of administrators.

## Defensive Measures
1. Enforce MFA on all accounts — especially privileged and internet-facing
2. Use hardware security keys (FIDO2/WebAuthn) for highest-value accounts
3. Implement account lockout after 5–10 failed attempts
4. Monitor for impossible travel (simultaneous logins from geographically distant IPs)
5. Disable legacy authentication protocols (Basic Auth, NTLM where possible)
6. Use passwordless authentication where supported (Windows Hello, FIDO2)

## Practice Challenge
1. Enable MFA on a personal account (email, GitHub, or cloud provider) using an authenticator app.
2. Test the recovery flow — what happens if you lose your MFA device?
3. Review what authentication methods are allowed in your lab Active Directory environment.
4. Attempt to identify NTLM authentication in a Wireshark capture from your lab.
