# W — Web Application Security

## Beginner Explanation
Web applications are a primary attack target because they are internet-accessible and handle sensitive data. Web application security focuses on building and testing apps to resist injection, authentication abuse, and data exposure.

## Technical Deep Dive
Full OWASP coverage: [04_Web_Security/OWASP_Top10.md](../04_Web_Security/OWASP_Top10.md)

### OWASP Top 10 (2021) Quick Reference
| Rank | Risk | Defense |
|------|------|---------|
| A01 | Broken Access Control | Deny by default; test every endpoint |
| A02 | Cryptographic Failures | TLS 1.2+; AES-256; no MD5 |
| A03 | Injection | Parameterized queries; output encoding |
| A04 | Insecure Design | Threat modeling during design |
| A05 | Security Misconfiguration | Hardening; disable defaults |
| A06 | Vulnerable Components | SCA scanning; dependency updates |
| A07 | Auth Failures | MFA; secure sessions |
| A08 | Software Integrity Failures | Verify signatures; supply chain checks |
| A09 | Logging/Monitoring Failures | Log all auth; alert anomalies |
| A10 | SSRF | Allowlist outbound; block cloud metadata endpoints |

### SQL Injection — Vulnerable vs. Safe
```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username='{username}'"
# SAFE — parameterized query
cursor.execute("SELECT * FROM users WHERE username=?", (username,))
```

### Essential Security Headers
```
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

### SAST/DAST in CI/CD
```yaml
- name: Semgrep SAST
  run: semgrep --config=p/owasp-top-ten --error .
- name: ZAP DAST
  uses: zaproxy/action-baseline@v0.9.0
  with:
    target: 'https://staging.yourapp.com'
```

## Real-World Relevance
**British Airways (2018):** Malicious JavaScript injected via a compromised supply-chain script stole 500,000 card numbers. A Content Security Policy blocking unauthorized scripts would have prevented it. GDPR fine: £20M.

## Defensive Measures
1. Use parameterized queries for all database interactions
2. Implement all security headers (CSP, HSTS, X-Frame-Options)
3. Run SAST in CI/CD and DAST against staging before each release
4. Conduct OWASP Top 10 penetration tests annually

## Practice Challenge
1. Set up DVWA (Damn Vulnerable Web Application) in a lab VM.
2. Exploit SQL Injection on the login form.
3. Fix it with a parameterized query and verify the exploit fails.
