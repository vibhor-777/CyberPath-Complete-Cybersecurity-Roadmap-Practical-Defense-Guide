# OWASP Top 10 — Defensive Technical Guide

> **Module:** [04 Web Security](./README.md) | **Back to root:** [Repository Root](../README.md)

The OWASP Top 10 is the most widely referenced list of critical web application security risks. This guide covers each category with attacker mechanics, real breach examples, and concrete developer/operator controls. **All examples are for defensive education only.**

---

## Table of Contents

1. [A01 — Broken Access Control](#a01--broken-access-control)
2. [A02 — Cryptographic Failures](#a02--cryptographic-failures)
3. [A03 — Injection](#a03--injection)
4. [A04 — Insecure Design](#a04--insecure-design)
5. [A05 — Security Misconfiguration](#a05--security-misconfiguration)
6. [A06 — Vulnerable and Outdated Components](#a06--vulnerable-and-outdated-components)
7. [A07 — Identification and Authentication Failures](#a07--identification-and-authentication-failures)
8. [A08 — Software and Data Integrity Failures](#a08--software-and-data-integrity-failures)
9. [A09 — Security Logging and Monitoring Failures](#a09--security-logging-and-monitoring-failures)
10. [A10 — Server-Side Request Forgery (SSRF)](#a10--server-side-request-forgery-ssrf)

---

## A01 — Broken Access Control

### Beginner Explanation

Access control is the set of rules that decides *who can do what* in your application. When these rules are broken or missing, users can access data or functions they shouldn't—like reading another user's private messages or escalating to admin privileges without authorization.

### Technical Deep Dive

**Insecure Direct Object Reference (IDOR)** is the most common form. The application exposes an internal identifier (database primary key, filename, UUID) directly in URLs or API calls, and never verifies whether the requesting user is authorized to access that specific object.

**Vulnerable example (Python/Flask):**

```python
# ❌ VULNERABLE — No ownership check
@app.route('/api/invoices/<int:invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = db.session.query(Invoice).get(invoice_id)
    return jsonify(invoice.to_dict())
    # Any authenticated user can increment invoice_id and see others' invoices
```

**Secure example with ownership check:**

```python
# ✅ SECURE — Enforce object-level authorization
@app.route('/api/invoices/<int:invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = db.session.query(Invoice).filter_by(
        id=invoice_id,
        owner_id=current_user.id   # enforce ownership at query level
    ).first_or_404()
    return jsonify(invoice.to_dict())
```

**Role-Based Access Control (RBAC) pattern:**

```python
# roles.py — centralized permission definitions
PERMISSIONS = {
    'viewer':    {'read'},
    'editor':    {'read', 'write'},
    'admin':     {'read', 'write', 'delete', 'manage_users'},
}

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if permission not in PERMISSIONS.get(current_user.role, set()):
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Usage
@app.route('/admin/users/<int:uid>', methods=['DELETE'])
@login_required
@require_permission('delete')
def delete_user(uid):
    ...
```

**Access Control List (ACL) check in middleware:**

```javascript
// Express.js middleware — resource-level ACL
async function authorizeResource(req, res, next) {
  const { resourceType, resourceId } = req.params;
  const userId = req.user.id;

  const allowed = await db.acl.findOne({
    subject: userId,
    object: `${resourceType}:${resourceId}`,
    action: req.method.toLowerCase(),
  });

  if (!allowed) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
}
```

**Horizontal vs Vertical privilege escalation:**

| Type | Description | Example |
|------|-------------|---------|
| Horizontal | Accessing another user's same-level resources | User A reads User B's profile |
| Vertical | Gaining higher-privilege actions | Normal user invokes admin endpoint |

### Real-World Relevance

- **Optus breach (2022):** An unauthenticated API endpoint returned customer PII when the sequential customer ID was incremented. No authentication or authorization check was enforced on the object retrieval path. ~9.8 million records exposed.
- **Parler (2021):** Sequential post IDs combined with no rate limiting allowed enumeration and archival of millions of posts including deleted content and metadata with GPS coordinates.
- **T-Mobile (2021):** An API exposed customer data via a query by MSISDN without checking whether the requesting session owned that number.

### Defensive Measures

- **Deny by default:** All access control decisions should default to *denied* unless explicitly permitted.
- **Server-side enforcement:** Never rely on hidden form fields, URL parameters, or client-side JavaScript for access decisions.
- **Use non-guessable identifiers:** UUIDs v4 instead of sequential integers reduce IDOR enumeration window.
- **Automated testing:** Include IDOR test cases in your CI pipeline using OWASP ZAP or custom scripts that swap session tokens.

```bash
# Quick IDOR test pattern with curl (lab environment)
TOKEN_USER_A="Bearer eyJ..."
TOKEN_USER_B="Bearer eyJ..."

# Get User A's resource ID
RESOURCE_ID=$(curl -s -H "Authorization: $TOKEN_USER_A" \
  https://app.example.com/api/invoices | jq -r '.[0].id')

# Attempt access with User B's token
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: $TOKEN_USER_B" \
  https://app.example.com/api/invoices/$RESOURCE_ID
# Should return 403, not 200
```

- **Log access control failures:** Every 403 at the object level is a potential IDOR probe.

### Practice Challenge

> Set up a simple Flask or Express app with two user accounts and an invoice endpoint. Verify that user B *cannot* retrieve user A's invoice by ID. Add a test that automatically validates this in your CI pipeline.

---

## A02 — Cryptographic Failures

### Beginner Explanation

Cryptographic failures happen when sensitive data is transmitted or stored without adequate encryption—or when outdated, weak algorithms are used that can be broken by modern computing.

### Technical Deep Dive

**Common failure patterns:**

| Failure | Risk | Mitigation |
|---------|------|-----------|
| HTTP instead of HTTPS | Traffic interception (MitM) | Enforce HTTPS, HSTS |
| MD5/SHA-1 for passwords | Rainbow table / GPU cracking | bcrypt, Argon2, scrypt |
| ECB mode encryption | Pattern leakage | AES-256-GCM |
| Hardcoded keys in source | Key exposure via repo leak | Secret manager + rotation |
| TLS 1.0/1.1 | BEAST, POODLE attacks | TLS 1.3 only |
| Self-signed certs in production | No CA validation possible | Trusted CA + cert pinning |

**Detecting weak cipher usage with openssl:**

```bash
# Check what TLS versions a server accepts
openssl s_client -connect example.com:443 -tls1   # Should FAIL on hardened server
openssl s_client -connect example.com:443 -tls1_1 # Should FAIL on hardened server
openssl s_client -connect example.com:443 -tls1_3 # Should SUCCEED

# Check cipher suites offered
nmap --script ssl-enum-ciphers -p 443 example.com
```

**Nginx TLS 1.3 hardening:**

```nginx
# /etc/nginx/conf.d/ssl.conf
ssl_protocols TLSv1.3;                         # TLS 1.3 only
ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';
ssl_prefer_server_ciphers off;                  # TLS 1.3 ignores this; good practice for 1.2 fallback configs
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
ssl_session_tickets off;                        # Disable session ticket reuse (forward secrecy)

# HSTS — tell browsers to always use HTTPS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

**Secure password storage:**

```python
# ❌ VULNERABLE
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# ❌ STILL VULNERABLE — SHA-256 without salt/work factor
password_hash = hashlib.sha256(password.encode()).hexdigest()

# ✅ SECURE — bcrypt with adaptive work factor
import bcrypt

def hash_password(plaintext: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)   # rounds=12 ≈ 300ms per hash on modern hardware
    return bcrypt.hashpw(plaintext.encode('utf-8'), salt)

def verify_password(plaintext: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(plaintext.encode('utf-8'), stored_hash)
```

**AES-256-GCM encryption of sensitive fields:**

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

def encrypt_field(plaintext: str, key: bytes) -> str:
    """Encrypt a string field with AES-256-GCM. key must be 32 bytes."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)           # 96-bit nonce, never reuse
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_field(token: str, key: bytes) -> str:
    data = base64.b64decode(token)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()
```

### Real-World Relevance

- **RockYou2021 / Adobe breach (2013):** Adobe stored ~153 million passwords using 3DES in ECB mode with no per-user salt. Identical passwords produced identical ciphertext blocks, enabling trivial cracking via frequency analysis.
- **LinkedIn (2012):** 6.5 million SHA-1 unsalted password hashes leaked. Cracked within hours because users with the same password had identical hashes.
- **Heartbleed (2014):** While a bug not a configuration issue, it demonstrated that even "encrypted" traffic can be trivially exposed when the TLS implementation is flawed—driving adoption of TLS 1.3.

### Defensive Measures

- **Classify data:** Identify all sensitive data (PII, payment, credentials, health). Apply appropriate protections per classification.
- **Don't invent cryptography:** Use established libraries (`cryptography`, `libsodium`, `Bouncy Castle`).
- **Key management:** Store keys in a dedicated secret manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Never in source code or `.env` files committed to version control.
- **Rotate keys:** Establish key rotation schedules. Use envelope encryption so rotating the Data Encryption Key (DEK) doesn't require re-encrypting all data.

### Practice Challenge

> Run `testssl.sh` or `ssllabs.com` against a web server you control. Identify any weak cipher suites or protocol versions. Harden the configuration to achieve an A+ rating. Document the before/after configuration diff.

---

## A03 — Injection

### Beginner Explanation

Injection happens when untrusted user input is interpreted as code or commands by the application. The two most dangerous forms are SQL injection (the database executes attacker-controlled SQL) and command injection (the OS executes attacker-controlled shell commands).

### Technical Deep Dive

#### SQL Injection

**How it works:**

```
Vulnerable query template:
  "SELECT * FROM users WHERE username='" + input + "'"

Attacker input:
  ' OR '1'='1

Resulting SQL:
  SELECT * FROM users WHERE username='' OR '1'='1'
  → Returns ALL users (authentication bypass)

Attacker input (data extraction):
  '; SELECT table_name FROM information_schema.tables--

Attacker input (destructive):
  '; DROP TABLE users;--
```

**Parameterized queries (the definitive fix):**

```python
# ❌ VULNERABLE — string concatenation
def get_user_vulnerable(username):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return db.execute(query).fetchone()

# ✅ SECURE — parameterized query (driver handles escaping)
def get_user_secure(username):
    query = "SELECT * FROM users WHERE username = %s"
    return db.execute(query, (username,)).fetchone()
```

```java
// Java — PreparedStatement
String sql = "SELECT * FROM accounts WHERE account_id = ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setInt(1, accountId);   // accountId is bound, not interpolated
ResultSet rs = stmt.executeQuery();
```

```javascript
// Node.js with pg (PostgreSQL)
const result = await pool.query(
  'SELECT * FROM orders WHERE user_id = $1 AND status = $2',
  [userId, status]  // parameters bound separately
);
```

**ORM usage (SQLAlchemy):**

```python
# ✅ SECURE — ORM builds safe queries automatically
user = db.session.query(User).filter(
    User.username == username,
    User.active == True
).first()

# ⚠️ DANGEROUS even in ORM — raw() bypasses protection
user = db.session.execute(
    text(f"SELECT * FROM users WHERE username = '{username}'")  # ❌
)
```

#### Command Injection

```python
# ❌ VULNERABLE — shell=True with user input
import subprocess
filename = request.args.get('file')
result = subprocess.run(f"cat /reports/{filename}", shell=True, capture_output=True)

# Attacker input: "../../etc/passwd" or "report.pdf; rm -rf /"

# ✅ SECURE — list form, no shell, validate input
import subprocess, re, os

def get_report(filename: str) -> bytes:
    # Allowlist validation: only alphanumeric, dash, underscore, dot
    if not re.match(r'^[a-zA-Z0-9_\-]+\.pdf$', filename):
        raise ValueError("Invalid filename")
    
    safe_path = os.path.realpath(os.path.join('/reports', filename))
    if not safe_path.startswith('/reports/'):
        raise ValueError("Path traversal detected")
    
    result = subprocess.run(
        ['cat', safe_path],    # list form — no shell interpretation
        capture_output=True,
        timeout=5
    )
    return result.stdout
```

#### WAF Rules for Injection (ModSecurity + OWASP CRS)

```apache
# modsecurity.conf — enable CRS rules for SQLi and command injection
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditLog /var/log/modsec_audit.log

# CRS rules 942xxx cover SQL injection
# CRS rules 932xxx cover OS command injection
# These are included automatically when you load crs-setup.conf + rules/

# Custom rule example: block common SQLi patterns in query string
SecRule ARGS "@detectSQLi" \
  "id:1001,phase:2,deny,status:400,\
   log,msg:'SQL Injection Attempt Detected',\
   tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION'"
```

### Real-World Relevance

- **Equifax (2017):** A combination of a vulnerable open-source component (Apache Struts CVE-2017-5638) with OGNL injection exposed 147 million consumer records. Command injection via HTTP headers was the initial entry point.
- **Sony Pictures (2014):** SQL injection in multiple web properties was used to pivot into internal networks, ultimately leading to one of the most damaging corporate breaches in history.
- **Heartland Payment Systems (2008):** SQL injection led to the theft of 130 million credit card numbers.

### Defensive Measures

1. **Parameterized queries / prepared statements** — the only reliable SQLi defense.
2. **Stored procedures with parameterization** — acceptable if the procedure itself doesn't build dynamic SQL.
3. **Input validation (allowlist)** — validate format, length, and character set. Never rely on this alone.
4. **Least privilege database accounts** — the app DB user should not have DROP, CREATE, or admin privileges.
5. **WAF as defense-in-depth** — not a substitute for parameterized queries.
6. **Static analysis (SAST):** Semgrep rules to detect string concatenation in query contexts.

```bash
# Semgrep — detect SQLi patterns in Python
semgrep --config "p/python-sql-injection" ./src/
```

### Practice Challenge

> ⚠️ **Lab Environment Only** — Use DVWA (Damn Vulnerable Web Application) or WebGoat. Enable SQL injection level *Low*. Use `sqlmap` to demonstrate the vulnerability, then switch the code to parameterized queries and verify that `sqlmap` can no longer extract data.

---

## A04 — Insecure Design

### Beginner Explanation

Insecure design means the application's architecture or business logic was never built with security in mind—not just a coding bug but a fundamental design flaw. No amount of secure coding fixes a broken design.

### Technical Deep Dive

**Threat modeling with STRIDE:**

| Threat | Description | Example |
|--------|-------------|---------|
| **S**poofing | Impersonating another entity | Forging a session token |
| **T**ampering | Modifying data | Changing a price in a POST body |
| **R**epudiation | Denying an action occurred | No audit log for fund transfers |
| **I**nformation disclosure | Exposing data unintentionally | Stack traces in error responses |
| **D**enial of service | Making service unavailable | No rate limiting on expensive operations |
| **E**levation of privilege | Gaining unintended permissions | Accessing admin functions as regular user |

**Threat modeling workflow (using OWASP Threat Dragon or draw.io):**

```
1. Define scope — what are we protecting?
2. Draw data flow diagram (DFD)
   - External entities (users, APIs, services)
   - Processes (application components)
   - Data stores (databases, caches, files)
   - Trust boundaries (network zones, auth boundaries)
3. Enumerate threats — apply STRIDE to each DFD element
4. Rate risk — Likelihood × Impact (use DREAD or CVSS)
5. Define mitigations — one per threat
6. Validate mitigations in design review and code review
```

**Secure SDLC integration points:**

```
Requirements    → Security requirements (auth, authz, data classification)
Design          → Threat modeling, architecture review
Development     → Secure coding standards, SAST in IDE
Testing         → DAST, penetration testing, code review
Deployment      → Infrastructure hardening, secrets management
Operations      → Monitoring, patch management, incident response
```

**Business logic flaw example:**

```python
# ❌ INSECURE DESIGN — coupon code with no per-user limit
@app.route('/checkout', methods=['POST'])
def checkout():
    coupon = request.json.get('coupon')
    if coupon == 'SAVE50':
        discount = 0.50
    order_total = cart_total * (1 - discount)
    # No check: has this user already used this coupon?
    # No check: is this coupon still active?
    # No check: does coupon apply to this product category?

# ✅ SECURE — enforce business rules at design level
@app.route('/checkout', methods=['POST'])
def checkout():
    coupon_code = request.json.get('coupon')
    coupon = validate_coupon(
        code=coupon_code,
        user_id=current_user.id,
        cart_items=current_cart,
        timestamp=datetime.utcnow()
    )  # validate_coupon checks: validity window, per-user limit, applicable categories
    ...
```

### Real-World Relevance

- **Venmo (historical):** Transactions were public by default and searchable. A design decision—not a bug—exposed financial behavior of millions of users.
- **Password reset flaws:** Many "forgot password" flows were designed without considering: link expiry, single-use tokens, or account enumeration via response differences.

### Defensive Measures

- **Threat model before writing code.** Use OWASP Threat Dragon (free, open-source).
- **Security requirements as acceptance criteria.** Every user story should have a corresponding security acceptance test.
- **Design review gate:** Significant new features require architect sign-off on threat model.
- **Reference architectures:** Use proven patterns (OAuth 2.0 for auth, not custom session schemes).

### Practice Challenge

> Pick any public web application (e.g., an open-source e-commerce app). Draw its data flow diagram. Apply STRIDE and identify at least three design-level security issues. Propose a mitigation for each. Document in a one-page threat model.

---

## A05 — Security Misconfiguration

### Beginner Explanation

Security misconfiguration is the most common vulnerability class. It includes leaving default credentials unchanged, exposing unnecessary services, showing detailed error messages to users, and leaving cloud storage publicly accessible.

### Technical Deep Dive

**Default credentials — common targets:**

```
Service           Default credentials
-----------       ------------------
Apache Tomcat     admin:admin, tomcat:tomcat
Jenkins           admin:<blank> (first-run setup token bypassed)
MySQL             root:<blank>
MongoDB           <none> (no auth by default in older versions)
Elasticsearch     <none> (no auth pre-6.8)
Grafana           admin:admin
RouterOS          admin:<blank>
```

**Detecting default credentials:**

```bash
# Check if Tomcat manager is exposed with default creds
curl -u admin:admin http://target:8080/manager/html
# Returns 200 → default credentials active ❌

# Nmap script to detect default credentials
nmap --script http-default-accounts -p 80,443,8080,8443 10.0.0.0/24
```

**Disabling directory listing (Apache):**

```apache
# /etc/apache2/apache2.conf or .htaccess
<Directory /var/www/html>
    Options -Indexes   # Disable directory listing
    AllowOverride None
    Require all granted
</Directory>
```

**Disabling directory listing (Nginx):**

```nginx
server {
    location / {
        autoindex off;   # Default is off; explicit for clarity
    }
}
```

**Suppressing verbose error messages:**

```python
# Flask — never expose stack traces in production
app.config['DEBUG'] = False
app.config['PROPAGATE_EXCEPTIONS'] = False

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f"Internal error: {e}", exc_info=True)  # log internally
    return jsonify({'error': 'An internal error occurred'}), 500  # generic to user
```

```nginx
# Nginx — hide server version
server_tokens off;
```

**Security headers checklist:**

```nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
```

**Automated misconfiguration scanning:**

```bash
# Lynis — Linux system hardening audit
lynis audit system

# Mozilla Observatory — web security headers
curl https://observatory.mozilla.org/api/v1/analyze?host=example.com

# Nikto — web server misconfiguration scanner
nikto -host https://example.com -ssl
```

### Real-World Relevance

- **Capital One (2019):** An SSRF vulnerability combined with an IAM misconfiguration allowed extraction of 100 million records from AWS S3. The EC2 instance had an overly permissive IAM role.
- **Microsoft Power Apps (2021):** Default table permissions in Microsoft Dataverse exposed data publicly for thousands of organizations including NHS contact tracing data.
- **Elasticsearch exposures (ongoing):** Thousands of Elasticsearch clusters run without authentication, discovered by search engines like Shodan within hours of exposure.

### Defensive Measures

- **Baseline configuration management:** Use Ansible, Chef, or Puppet to enforce hardened baselines. Deviation from baseline triggers alerts.
- **Change default credentials immediately** during provisioning (automate via IaC).
- **Disable unused services/ports:** Principle of minimal footprint.
- **Automated scanning in CI/CD:** Run Lynis, Trivy (for containers), or Prowler (for AWS) on every deployment.

```bash
# Prowler — AWS security misconfiguration scanner
prowler aws --compliance cis_aws_benchmark_level_2
```

### Practice Challenge

> Deploy a fresh Apache or Nginx server (VM or container). Run Nikto and Mozilla Observatory against it. Identify and remediate all findings. Achieve a minimum B+ on Observatory. Document every change made.

---

## A06 — Vulnerable and Outdated Components

### Beginner Explanation

Modern applications depend on dozens of third-party libraries, frameworks, and services. When any of these contains a known vulnerability, your application inherits that vulnerability even if your own code is perfect.

### Technical Deep Dive

**Dependency scanning with OWASP Dependency-Check:**

```bash
# Install and run
wget https://github.com/jeremylong/DependencyCheck/releases/latest/download/dependency-check-*.zip
unzip dependency-check-*.zip

./dependency-check/bin/dependency-check.sh \
  --project "MyApp" \
  --scan ./lib \
  --format HTML \
  --out ./reports/

# Output: HTML report listing CVEs per dependency
```

**NPM audit (Node.js):**

```bash
npm audit
npm audit --audit-level=high   # fail on high/critical only
npm audit fix                  # auto-fix where possible
```

**Python safety / pip-audit:**

```bash
pip install pip-audit
pip-audit --requirement requirements.txt --output json > audit-results.json
```

**Maven (Java):**

```xml
<!-- pom.xml — OWASP dependency check plugin -->
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>9.0.9</version>
  <configuration>
    <failBuildOnCVSS>7</failBuildOnCVSS>  <!-- fail build if CVSS >= 7 -->
    <format>HTML</format>
  </configuration>
</plugin>
```

**CI/CD integration (GitHub Actions):**

```yaml
# .github/workflows/dependency-scan.yml
name: Dependency Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run pip-audit
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt --fail-on-vuln
      - name: Run npm audit
        run: npm audit --audit-level=high
```

**Software Bill of Materials (SBOM):**

```bash
# Generate SBOM with Syft
syft dir:. -o spdx-json > sbom.json

# Check SBOM against vulnerability database with Grype
grype sbom:sbom.json
```

### Real-World Relevance

- **Log4Shell (CVE-2021-44228):** A single critical vulnerability in the ubiquitous Log4j library affected millions of Java applications worldwide. Full RCE via a single log message. Organizations without dependency inventories couldn't even answer "are we affected?"
- **Equifax (2017):** Apache Struts CVE-2017-5638 was patched 2 months before the breach. Equifax failed to apply the patch, resulting in the largest known consumer data breach.
- **SolarWinds (2020):** Vulnerable build pipeline dependencies were used to deliver a trojaned update to ~18,000 organizations.

### Defensive Measures

- **Inventory all dependencies** (direct and transitive). Generate SBOMs on every build.
- **Automate scanning** in CI/CD. Block merges that introduce high/critical CVEs.
- **Patch promptly:** High/Critical CVEs should be patched within 24-72 hours.
- **Subscribe to security advisories** for your key dependencies (GitHub Security Advisories, NVD feeds).
- **Minimize dependencies:** Every dependency is an attack surface. Evaluate whether you need it.

### Practice Challenge

> Take a public open-source web application. Run `npm audit` or `pip-audit`. Find a dependency with a known CVE. Research the CVE, understand its impact, then update the dependency and verify the vulnerability is resolved.

---

## A07 — Identification and Authentication Failures

### Beginner Explanation

Authentication failures include weak passwords, missing multi-factor authentication, session tokens that don't expire, and insecure "forgot password" flows. These failures let attackers impersonate legitimate users.

### Technical Deep Dive

**Multi-Factor Authentication (MFA):**

```python
# TOTP (Time-based One-Time Password) with pyotp
import pyotp, qrcode

def setup_mfa(user):
    secret = pyotp.random_base32()
    user.mfa_secret = secret  # store encrypted in DB
    
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="MyApp"
    )
    # Generate QR code for authenticator app enrollment
    img = qrcode.make(uri)
    return img, secret

def verify_mfa(user, code: str) -> bool:
    totp = pyotp.TOTP(user.mfa_secret)
    return totp.verify(code, valid_window=1)  # ±30 seconds tolerance
```

**Secure session management:**

```python
# Flask-Login secure session configuration
app.config.update(
    SECRET_KEY=os.environ['SESSION_SECRET'],   # 32+ random bytes
    SESSION_COOKIE_SECURE=True,                # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,              # No JS access
    SESSION_COOKIE_SAMESITE='Lax',            # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # Session timeout
    SESSION_COOKIE_NAME='__Host-session',      # __Host prefix security
)

# Regenerate session ID after login (session fixation prevention)
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        session.clear()        # Destroy old session
        login_user(user)       # Creates new session ID
        return redirect(url_for('dashboard'))
```

**Account lockout and rate limiting:**

```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")   # 5 attempts per IP per minute
def login():
    ...

# Progressive lockout
def check_lockout(username: str) -> bool:
    attempts = cache.get(f"login_attempts:{username}", 0)
    if attempts >= 10:
        lockout_until = cache.get(f"lockout_until:{username}")
        if lockout_until and datetime.utcnow() < lockout_until:
            raise AuthError("Account temporarily locked")
    return True
```

**Secure password storage comparison:**

```python
# Algorithm comparison
# MD5:     crackable in milliseconds with GPU
# SHA-256: crackable quickly without salt
# bcrypt:  ~300ms per hash with rounds=12, adaptive
# scrypt:  memory-hard, resistant to ASIC attacks
# Argon2:  PHC winner, memory+time+parallelism parameters

# Recommended: Argon2id (or bcrypt as widely-supported fallback)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(
    time_cost=3,       # iterations
    memory_cost=65536, # 64 MB
    parallelism=4,     # threads
)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False
```

**Secure "forgot password" flow:**

```python
import secrets, hashlib
from datetime import datetime, timedelta

def initiate_password_reset(email: str):
    user = User.query.filter_by(email=email).first()
    # Always return the same response regardless of whether email exists
    # (prevents account enumeration)
    
    if user:
        token = secrets.token_urlsafe(32)        # 256-bit random token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        user.reset_token_hash = token_hash
        user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
        send_reset_email(user.email, token)      # send plain token in link
    
    return "If that email exists, a reset link has been sent."

def complete_password_reset(token: str, new_password: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    user = User.query.filter_by(reset_token_hash=token_hash).first()
    
    if not user or user.reset_token_expiry < datetime.utcnow():
        raise AuthError("Invalid or expired reset token")
    
    user.password_hash = hash_password(new_password)
    user.reset_token_hash = None    # invalidate token immediately after use
    user.reset_token_expiry = None
    db.session.commit()
```

### Real-World Relevance

- **RockYou (2009):** 32 million passwords stored in plaintext. The leaked list became the default wordlist for password cracking and is still used today.
- **Dropbox (2012, disclosed 2016):** 68 million SHA-1 hashed passwords (half unsalted) leaked. Demonstrates that time-to-disclosure of a breach can be years.
- **Microsoft (2021):** Customer support tool was accessed via credential stuffing—credentials from unrelated breach reused against Microsoft systems.

### Defensive Measures

- **Enforce MFA** for all privileged accounts; strongly encourage for all users.
- **Never store plaintext passwords.** Use Argon2id or bcrypt.
- **Implement account lockout and rate limiting** on all authentication endpoints.
- **Use secure, random session tokens** (min 128 bits entropy). Rotate after privilege change.
- **Check passwords against known breached lists** using the HaveIBeenPwned k-anonymity API.

```python
# Check password against HIBP Pwned Passwords API (k-anonymity)
import hashlib, requests

def is_password_pwned(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    for line in resp.text.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return int(count)
    return 0
```

### Practice Challenge

> Implement a complete authentication flow in a web framework of your choice with: Argon2id password hashing, TOTP-based MFA, session rotation post-login, and rate limiting on the login endpoint. Write unit tests for each security control.

---

## A08 — Software and Data Integrity Failures

### Beginner Explanation

Integrity failures happen when code or data can be modified without detection—whether through untrusted update mechanisms, compromised CI/CD pipelines, or missing signature verification on software components.

### Technical Deep Dive

**Subresource Integrity (SRI) for CDN-hosted assets:**

```html
<!-- ❌ VULNERABLE — no integrity check -->
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>

<!-- ✅ SECURE — SRI hash ensures file matches expected content -->
<script
  src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"
  integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo="
  crossorigin="anonymous">
</script>
```

```bash
# Generate SRI hash for a local file
openssl dgst -sha256 -binary jquery.min.js | openssl base64 -A
# Output: sha256-<base64hash>
```

**Signed Git commits:**

```bash
# Set up GPG signing for commits
gpg --full-generate-key
git config --global user.signingkey <YOUR_KEY_ID>
git config --global commit.gpgsign true

# Verify a commit signature
git log --show-signature -1

# GitHub: require signed commits via branch protection rule
# Settings → Branches → Branch protection → "Require signed commits"
```

**Supply chain security — verifying package integrity:**

```bash
# npm — verify package integrity
npm install --audit
# npm automatically validates sha512 checksums from package-lock.json

# Python — verify package with hash
pip install --require-hashes -r requirements.txt
# requirements.txt with hashes:
# requests==2.31.0 \
#   --hash=sha256:58cd2187423d185b9998cf8b4b01575...

# Generate hashed requirements
pip-compile --generate-hashes requirements.in
```

**Secure CI/CD pipeline integrity:**

```yaml
# GitHub Actions — pin actions to full commit SHA (not floating tags)
# ❌ RISKY — tag can be moved
- uses: actions/checkout@v4

# ✅ SECURE — pinned to immutable commit SHA
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

# Sign and verify container images with Cosign
- name: Sign container image
  run: |
    cosign sign --key cosign.key \
      ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}

- name: Verify container image
  run: |
    cosign verify --key cosign.pub \
      ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
```

**Insecure deserialization:**

```python
# ❌ VULNERABLE — pickle deserializes arbitrary Python objects
import pickle
data = pickle.loads(user_supplied_bytes)  # RCE if input is malicious

# ✅ SECURE — use JSON or validated schema deserializers
import json
from pydantic import BaseModel

class UserPreferences(BaseModel):
    theme: str
    language: str
    notifications: bool

data = UserPreferences.parse_raw(user_supplied_json)  # strict schema validation
```

### Real-World Relevance

- **SolarWinds Orion (2020):** Malicious code (`SUNBURST`) was injected into the build pipeline and signed with SolarWinds' legitimate code signing certificate. ~18,000 organizations installed the backdoored update.
- **event-stream npm package (2018):** A malicious maintainer injected cryptocurrency-stealing code into a popular npm package that was downloaded millions of times.
- **codecov (2021):** CI/CD script was tampered with to exfiltrate environment variables (including secrets) from thousands of build pipelines.

### Defensive Measures

- **Always verify SRI hashes** for externally hosted scripts and stylesheets.
- **Sign all software releases** (GPG, Sigstore/Cosign for containers).
- **Pin dependencies** to exact versions with hash verification.
- **Protect build pipelines:** Restrict who can modify CI/CD config. Use short-lived credentials in pipelines, not long-lived secrets.
- **SLSA framework:** Adopt Supply-chain Levels for Software Artifacts (SLSA) for progressive supply chain hardening.

### Practice Challenge

> Audit a public GitHub Actions workflow. Identify any actions pinned to floating tags. Update them to use full commit SHAs. Add SRI hashes to any CDN-hosted scripts in an HTML file you own.

---

## A09 — Security Logging and Monitoring Failures

### Beginner Explanation

If you can't see what's happening in your application, you can't detect an attack, investigate a breach, or prove what happened in court. Logging failures mean attacks go undetected for months—the average breach dwell time is still measured in months, not hours.

### Technical Deep Dive

**What to log (mandatory events):**

```python
# Structured logging with security-relevant fields
import structlog, json
from datetime import datetime

logger = structlog.get_logger()

# Authentication events
logger.info("auth.login.success",
    user_id=user.id,
    ip=request.remote_addr,
    user_agent=request.headers.get('User-Agent'),
    timestamp=datetime.utcnow().isoformat(),
    session_id=session.sid
)

logger.warning("auth.login.failure",
    username=attempted_username,   # NOT the password
    ip=request.remote_addr,
    failure_reason="invalid_credentials",
    timestamp=datetime.utcnow().isoformat()
)

# Authorization events
logger.warning("authz.access.denied",
    user_id=current_user.id,
    resource=f"invoice:{invoice_id}",
    action="read",
    ip=request.remote_addr
)

# Data events
logger.info("data.export",
    user_id=current_user.id,
    record_count=len(results),
    export_format="csv",
    filter_criteria=str(filters)
)

# Admin events — always log
logger.warning("admin.user.deleted",
    actor_id=current_user.id,
    target_user_id=uid,
    ip=request.remote_addr
)
```

**Mandatory log fields:**

| Field | Purpose |
|-------|---------|
| `timestamp` (UTC, ISO 8601) | Correlation across time zones |
| `user_id` / `session_id` | Attribution |
| `ip_address` | Source identification |
| `event_type` | Categorization |
| `resource` | What was accessed |
| `action` | What was done |
| `outcome` (success/failure) | Result |
| `correlation_id` | Trace a request across services |

**What NOT to log:**

```python
# ❌ NEVER LOG THESE
logger.info("login", password=request.form['password'])     # plaintext credential
logger.info("payment", card_number=card.number)             # PAN (PCI violation)
logger.info("user", ssn=user.ssn)                          # SSN (PII)
logger.info("token", jwt=request.headers['Authorization'])  # bearer token
```

**Log retention policy:**

```
Security events:     Minimum 12 months online, 7 years cold storage
Access logs:         90 days online, 12 months cold storage
Application logs:    30-90 days online
Compliance (PCI/HIPAA): consult specific regulatory requirements
```

**Shipping logs to SIEM (Elasticsearch/Splunk):**

```yaml
# Filebeat configuration — ship application logs to Elasticsearch
filebeat.inputs:
  - type: log
    paths:
      - /var/log/myapp/*.log
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["https://elk.internal:9200"]
  ssl.certificate_authorities: ["/etc/ssl/certs/ca.crt"]
  username: "${ELASTIC_USER}"
  password: "${ELASTIC_PASS}"
```

**Detection rules (example — brute force):**

```
# Splunk SPL — detect 10+ failed logins in 5 minutes from same IP
index=application event_type=auth.login.failure
| bin _time span=5m
| stats count by src_ip _time
| where count > 10
| alert
```

### Real-World Relevance

- **Target (2013):** Attackers were active for 3 weeks before detection. Monitoring tools had flagged suspicious activity, but alerts were ignored or misclassified. 40 million card records stolen.
- **Uber (2016, disclosed 2022):** The 57-million-record breach was concealed for over a year, in part because logging was insufficient to determine scope. Uber paid attackers $100,000 to delete the data.
- **Average breach dwell time (IBM Cost of a Data Breach 2023):** 204 days to identify, 73 days to contain = 277 days total.

### Defensive Measures

- **Centralize logs** in an immutable SIEM (attackers cannot delete evidence).
- **Alert on security-critical events** immediately: multiple auth failures, privilege escalation, mass data export.
- **Protect log integrity:** Ship logs off-system in real time. Local log files can be wiped by an attacker.
- **Test your alerting:** Regularly simulate events to verify alerts fire correctly.
- **Rotate log analysis:** Periodically review logs for subtle anomalies that don't trigger automated alerts.

### Practice Challenge

> Configure structured JSON logging for a simple web application. Implement at minimum: login success/failure, access denied events, and admin actions. Set up a Filebeat → Elasticsearch pipeline and create a Kibana dashboard showing authentication failures by IP over time.

---

## A10 — Server-Side Request Forgery (SSRF)

### Beginner Explanation

SSRF tricks a server into making HTTP requests on behalf of an attacker. This lets attackers scan internal networks, access metadata services (AWS, Azure, GCP), and reach services behind firewalls that they couldn't access directly.

### Technical Deep Dive

**SSRF mechanism:**

```
Attacker sends:
  POST /api/fetch-preview
  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

Application code:
  response = requests.get(user_supplied_url)  # ❌ fetches AWS metadata!
  return response.text

Attacker receives:
  AWS IAM role credentials → full AWS account takeover
```

**Common SSRF targets:**

```
AWS metadata:   http://169.254.169.254/latest/meta-data/
Azure metadata: http://169.254.169.254/metadata/instance?api-version=2021-02-01
GCP metadata:   http://metadata.google.internal/computeMetadata/v1/
Kubernetes API: https://kubernetes.default.svc/api/
Internal Redis: redis://redis.internal:6379
Internal admin: http://admin.internal/
```

**SSRF mitigation — URL validation:**

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'https'}
BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local / metadata
    ipaddress.ip_network('127.0.0.0/8'),       # Loopback
    ipaddress.ip_network('::1/128'),           # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),          # IPv6 private
]

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        
        # Scheme allowlist
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False
        
        # Resolve hostname to IP
        hostname = parsed.hostname
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        
        # Block private/internal ranges
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return False
        
        return True
    except Exception:
        return False

def fetch_preview(url: str) -> str:
    if not is_safe_url(url):
        raise ValueError("URL is not permitted")
    
    # Use a dedicated outbound-only HTTP client with no internal network access
    response = requests.get(url, timeout=5, allow_redirects=False)
    return response.text
```

**Network-level SSRF mitigation:**

```hcl
# AWS — IMDSv2 requirement (requires token for metadata access)
# Prevents SSRF from accessing EC2 metadata without PUT request first
resource "aws_instance" "app" {
  # ...
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 enforced
    http_put_response_hop_limit = 1           # Blocks containers from reaching metadata
  }
}
```

```bash
# Verify IMDSv2 is enforced on running instance
# IMDSv1 (no token required) should fail:
curl http://169.254.169.254/latest/meta-data/  # Should fail with 401

# IMDSv2 (requires token):
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

**WAF rule for SSRF metadata endpoint blocking:**

```apache
# ModSecurity — block requests targeting cloud metadata endpoints
SecRule REQUEST_URI|ARGS|REQUEST_HEADERS "@rx 169\.254\.169\.254" \
  "id:9001,phase:2,deny,status:400,\
   log,msg:'Potential SSRF - metadata endpoint in request'"

SecRule REQUEST_URI|ARGS "@rx metadata\.google\.internal" \
  "id:9002,phase:2,deny,status:400,\
   log,msg:'Potential SSRF - GCP metadata endpoint'"
```

### Real-World Relevance

- **Capital One (2019):** The primary attack vector was SSRF via a misconfigured WAF (AWS WAF → EC2 → metadata service). The IAM role attached to the instance had excessive S3 permissions. Combined SSRF + IAM misconfiguration = 100M+ records stolen.
- **GitLab (2021, CVE-2021-22214):** SSRF allowed unauthenticated access to internal services via GitLab's Webhooks feature.
- **SSRF in PDF generators:** Many "generate PDF from URL" features are SSRF vectors when not properly isolated.

### Defensive Measures

- **URL allowlisting** is far more secure than blocklisting (attackers can bypass blocklists).
- **Enforce IMDSv2** on all cloud instances.
- **Network segmentation:** Application servers should not have direct access to internal management networks.
- **Egress filtering:** Restrict outbound connectivity from application servers to only required external services.
- **Dedicated fetch service:** Run URL-fetching in a sandboxed, network-isolated container with no access to internal services.

### Practice Challenge

> ⚠️ **Lab Environment Only** — Set up a vulnerable Flask application that fetches user-supplied URLs. Demonstrate SSRF by fetching a "metadata service" running locally (simulate with a simple HTTP server on 169.254.x.x or localhost). Then implement the URL validation function above and verify the attack is blocked.

---

## 📊 OWASP Top 10 Quick Reference

| # | Category | Key Control |
|---|----------|-------------|
| A01 | Broken Access Control | Object-level authorization on every request |
| A02 | Cryptographic Failures | TLS 1.3, Argon2id/bcrypt, AES-256-GCM |
| A03 | Injection | Parameterized queries, input validation |
| A04 | Insecure Design | Threat modeling, secure SDLC |
| A05 | Security Misconfiguration | Hardened baselines, disable defaults |
| A06 | Vulnerable Components | SBOM, automated scanning, prompt patching |
| A07 | Auth Failures | MFA, session management, secure storage |
| A08 | Integrity Failures | SRI, signed builds, pinned dependencies |
| A09 | Logging Failures | Structured logs, SIEM, real-time alerting |
| A10 | SSRF | URL allowlisting, IMDSv2, egress filtering |

---

*Part of the [CyberPath Defensive Security Roadmap](../README.md)*
