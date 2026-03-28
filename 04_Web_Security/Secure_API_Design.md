# Secure API Design

> **Module:** [04 Web Security](./README.md) | **Back to root:** [Repository Root](../README.md)

APIs are the backbone of modern applications—and one of the most targeted attack surfaces. This guide covers the full lifecycle of API security: authentication, authorization, input validation, transport security, monitoring, and the OWASP API Security Top 10.

---

## Table of Contents

1. [API Authentication](#1-api-authentication)
   - [OAuth 2.0](#oauth-20)
   - [API Keys](#api-keys)
   - [JWT Best Practices](#jwt-best-practices)
2. [Rate Limiting and Throttling](#2-rate-limiting-and-throttling)
3. [Input Validation and Schema Validation](#3-input-validation-and-schema-validation)
4. [Security Headers for APIs](#4-security-headers-for-apis)
5. [CORS Policy](#5-cors-policy)
6. [API Versioning and Deprecation Security](#6-api-versioning-and-deprecation-security)
7. [Common API Attacks](#7-common-api-attacks)
8. [OWASP API Security Top 10](#8-owasp-api-security-top-10)

---

## 1. API Authentication

### Beginner Explanation

Authentication is the process of proving who you are to an API. Without it, any internet user could call your API as if they were a legitimate customer. The three main mechanisms are: OAuth 2.0 (delegated access for third-party integrations), API keys (service-to-service), and JWTs (token-based sessions).

### OAuth 2.0

OAuth 2.0 is a *delegation* framework—it lets a user grant a third-party application limited access to their account without sharing their password.

**Authorization Code Flow with PKCE (recommended for public clients):**

```
1. Client generates code_verifier (random 32 bytes, base64url encoded)
   code_challenge = BASE64URL(SHA-256(code_verifier))

2. Redirect user to:
   GET /authorize
     ?response_type=code
     &client_id=APP_CLIENT_ID
     &redirect_uri=https://app.example.com/callback
     &scope=openid profile email
     &state=RANDOM_CSRF_TOKEN
     &code_challenge=<code_challenge>
     &code_challenge_method=S256

3. User authenticates at Authorization Server → receives auth code

4. Client exchanges code for tokens:
   POST /token
     grant_type=authorization_code
     &code=AUTH_CODE
     &redirect_uri=https://app.example.com/callback
     &client_id=APP_CLIENT_ID
     &code_verifier=<original_code_verifier>

5. Server validates: SHA-256(code_verifier) == stored code_challenge
6. Returns: access_token, refresh_token, id_token
```

**OAuth 2.0 token validation middleware (Node.js):**

```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  jwksUri: 'https://auth.example.com/.well-known/jwks.json',
  cache: true,
  cacheMaxAge: 3600000,  // 1 hour
});

function getSigningKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key?.publicKey || key?.rsaPublicKey;
    callback(null, signingKey);
  });
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }
  
  const token = authHeader.substring(7);
  jwt.verify(token, getSigningKey, {
    audience: 'https://api.example.com',    // validate aud claim
    issuer: 'https://auth.example.com',     // validate iss claim
    algorithms: ['RS256'],                   // reject HS256 and none
  }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}
```

**OAuth 2.0 scope enforcement:**

```python
# FastAPI + OAuth 2.0 scope validation
from fastapi import Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, SecurityScopes

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/token",
    scopes={
        "invoices:read": "Read invoices",
        "invoices:write": "Create and modify invoices",
        "admin": "Administrative access",
    }
)

def verify_token_scopes(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme)
):
    payload = decode_and_validate_jwt(token)
    token_scopes = payload.get("scope", "").split()
    
    for scope in security_scopes.scopes:
        if scope not in token_scopes:
            raise HTTPException(
                status_code=403,
                detail=f"Required scope: {scope}",
                headers={"WWW-Authenticate": f'Bearer scope="{security_scopes.scope_str}"'},
            )
    return payload

@router.get("/invoices", dependencies=[Security(verify_token_scopes, scopes=["invoices:read"])])
def list_invoices():
    ...
```

### API Keys

API keys are opaque tokens for service-to-service authentication. They don't carry identity information themselves but are looked up in a database.

```python
# Secure API key generation and storage
import secrets, hashlib

def generate_api_key() -> tuple[str, str]:
    """Returns (plain_key_for_user, hashed_key_for_storage)"""
    key = f"sk_{secrets.token_urlsafe(32)}"  # prefix helps identify leaked keys
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, key_hash

# Validation middleware
def validate_api_key(request):
    api_key = request.headers.get('X-API-Key') or \
              request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    key_record = db.query(ApiKey).filter_by(
        key_hash=key_hash,
        active=True
    ).first()
    
    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Update last-used timestamp for audit
    key_record.last_used_at = datetime.utcnow()
    db.commit()
    
    return key_record.owner
```

**API key security checklist:**

- ✅ Hash keys before storing (SHA-256 minimum)
- ✅ Use a recognizable prefix (`sk_`, `pk_`, `api_`) to enable GitHub secret scanning
- ✅ Scope keys to minimum required permissions
- ✅ Support key rotation without downtime (allow two active keys briefly)
- ✅ Log every key usage with timestamp and source IP
- ✅ Implement key expiry

### JWT Best Practices

**Common JWT vulnerabilities and fixes:**

```python
# ❌ VULNERABILITY 1: Algorithm confusion — accepting "none"
import jwt

# Attacker sends: header.alg = "none", removes signature
decoded = jwt.decode(token, options={"verify_signature": False})  # NEVER

# ✅ FIX: Always specify allowed algorithms
decoded = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],       # allowlist only strong algorithms
    audience="https://api.example.com",
    options={"require": ["exp", "iat", "iss", "aud"]}  # require standard claims
)

# ❌ VULNERABILITY 2: Symmetric key used for asymmetric JWT
# Attacker tricks server into verifying RS256 token with HS256 using server's public key as secret
# ✅ FIX: Explicitly specify algorithm family; never accept HS256 for tokens signed with RS256

# ❌ VULNERABILITY 3: Missing expiry
payload = {"sub": user_id}  # no exp claim → tokens never expire

# ✅ FIX: Short-lived access tokens, longer refresh tokens
from datetime import datetime, timedelta, timezone

payload = {
    "sub": str(user_id),
    "iat": datetime.now(timezone.utc),
    "exp": datetime.now(timezone.utc) + timedelta(minutes=15),  # access: 15 min
    "iss": "https://auth.example.com",
    "aud": "https://api.example.com",
    "jti": str(uuid4()),   # JWT ID — enables token revocation
}
```

**JWT token revocation (stateless tokens have no built-in revocation):**

```python
# Approach: maintain a blocklist of revoked JTI (JWT ID) claims
import redis

r = redis.Redis(host='redis.internal')

def revoke_token(jti: str, expiry: datetime):
    """Add JTI to blocklist until token naturally expires."""
    ttl = int((expiry - datetime.now(timezone.utc)).total_seconds())
    if ttl > 0:
        r.setex(f"revoked_jti:{jti}", ttl, "1")

def is_token_revoked(jti: str) -> bool:
    return r.exists(f"revoked_jti:{jti}") == 1

# In validation middleware
def validate_jwt(token: str):
    payload = jwt.decode(token, public_key, algorithms=["RS256"], ...)
    if is_token_revoked(payload['jti']):
        raise HTTPException(401, "Token has been revoked")
    return payload
```

### Real-World Relevance

- **Twitter API (2022):** An API endpoint allowed querying user data by email or phone without authentication, exposing 5.4 million accounts via an IDOR on the lookup endpoint.
- **Peloton (2021):** Unauthenticated API endpoints returned user profile data including age, gender, weight, and workout history.

### Practice Challenge

> Implement an OAuth 2.0 Authorization Code + PKCE flow for a simple app. Verify that: (1) tokens with algorithm "none" are rejected, (2) expired tokens return 401, (3) tokens with incorrect audience are rejected. Write automated tests for each case.

---

## 2. Rate Limiting and Throttling

### Beginner Explanation

Rate limiting prevents abuse by capping how many requests a client can make in a time window. Without it, attackers can brute-force credentials, enumerate user data, or overwhelm your service with requests.

### Technical Deep Dive

**Rate limiting strategies:**

| Strategy | Description | Use Case |
|----------|-------------|---------|
| Fixed window | N requests per M seconds, counter resets | Simple general-purpose limiting |
| Sliding window | Rolling time window | More accurate, prevents burst at window edge |
| Token bucket | Tokens accumulate, consumed per request | Burst-friendly with sustained rate limit |
| Leaky bucket | Queue drains at fixed rate | Smooth output rate |

**Implementation with Redis (token bucket):**

```python
import redis, time

r = redis.Redis(host='redis.internal')

def check_rate_limit(
    key: str,
    limit: int,
    window_seconds: int
) -> tuple[bool, dict]:
    """
    Sliding window rate limiter using Redis sorted sets.
    Returns (is_allowed, rate_limit_headers)
    """
    now = time.time()
    window_start = now - window_seconds
    
    pipe = r.pipeline()
    pipe.zremrangebyscore(key, 0, window_start)   # remove old entries
    pipe.zadd(key, {str(now): now})               # add current request
    pipe.zcard(key)                               # count requests in window
    pipe.expire(key, window_seconds)              # auto-cleanup
    _, _, count, _ = pipe.execute()
    
    headers = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, limit - count)),
        "X-RateLimit-Reset": str(int(now + window_seconds)),
    }
    
    return count <= limit, headers

# FastAPI middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    path = request.url.path
    
    # Different limits for different endpoint sensitivity
    limits = {
        "/api/auth/login": (5, 60),      # 5 per minute — brute force protection
        "/api/auth/register": (3, 3600), # 3 per hour — account creation abuse
        "/api/": (1000, 3600),            # 1000/hour general API
    }
    
    for prefix, (limit, window) in limits.items():
        if path.startswith(prefix):
            key = f"ratelimit:{client_ip}:{prefix}"
            allowed, headers = check_rate_limit(key, limit, window)
            
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded", "retry_after": window},
                    headers={**headers, "Retry-After": str(window)}
                )
            break
    
    response = await call_next(request)
    return response
```

**Nginx-level rate limiting:**

```nginx
# nginx.conf
http {
    # Define rate limit zones
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    limit_req_zone $http_x_api_key zone=api_key:10m rate=1000r/h;
    
    server {
        location /api/auth/login {
            limit_req zone=login burst=2 nodelay;
            limit_req_status 429;
            proxy_pass http://backend;
        }
        
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            limit_req_status 429;
            proxy_pass http://backend;
        }
    }
}
```

**Rate limit response headers (standard):**

```
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704067200
Retry-After: 60
Content-Type: application/json

{"error": "rate_limit_exceeded", "message": "Too many requests. Try again in 60 seconds."}
```

### Defensive Measures

- **Rate limit per user AND per IP** (authenticated + unauthenticated paths).
- **Apply lower limits to sensitive endpoints** (auth, password reset, OTP verification).
- **Log rate limit breaches** — patterns of 429s are attack indicators.
- **Implement exponential backoff** in client libraries to be good citizens.

### Practice Challenge

> Implement sliding window rate limiting on a login endpoint. Simulate a brute force attack with a script making 100 requests per minute. Verify that requests above the limit receive 429 responses and legitimate traffic is unaffected after the window resets.

---

## 3. Input Validation and Schema Validation

### Beginner Explanation

Every field in every API request is a potential attack vector. Input validation ensures that data conforms to expected types, lengths, formats, and ranges before it ever touches business logic or a database.

### Technical Deep Dive

**Schema validation with Pydantic (Python/FastAPI):**

```python
from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional
import re

class CreateOrderRequest(BaseModel):
    customer_email: EmailStr                           # validates email format
    product_id: str = Field(..., regex=r'^prod_[a-z0-9]{16}$')  # strict format
    quantity: int = Field(..., ge=1, le=100)           # 1-100 inclusive
    shipping_address: str = Field(..., min_length=10, max_length=500)
    promo_code: Optional[str] = Field(None, max_length=20, regex=r'^[A-Z0-9]+$')
    
    @validator('shipping_address')
    def sanitize_address(cls, v):
        # Strip HTML tags that could cause XSS if rendered
        cleaned = re.sub(r'<[^>]+>', '', v)
        if cleaned != v:
            raise ValueError("HTML not allowed in address fields")
        return cleaned
    
    class Config:
        # Reject extra fields not in schema (mass assignment protection)
        extra = 'forbid'

@router.post("/orders")
def create_order(order: CreateOrderRequest):
    # At this point, all fields are validated and typed correctly
    ...
```

**JSON Schema validation (language-agnostic):**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "CreateOrder",
  "type": "object",
  "required": ["customer_email", "product_id", "quantity"],
  "additionalProperties": false,
  "properties": {
    "customer_email": {
      "type": "string",
      "format": "email",
      "maxLength": 254
    },
    "product_id": {
      "type": "string",
      "pattern": "^prod_[a-z0-9]{16}$"
    },
    "quantity": {
      "type": "integer",
      "minimum": 1,
      "maximum": 100
    },
    "promo_code": {
      "type": "string",
      "pattern": "^[A-Z0-9]{4,20}$"
    }
  }
}
```

**Express.js with ajv schema validation:**

```javascript
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const ajv = new Ajv({ allErrors: true, strict: true });
addFormats(ajv);

const orderSchema = {
  type: 'object',
  required: ['customer_email', 'product_id', 'quantity'],
  additionalProperties: false,   // mass assignment protection
  properties: {
    customer_email: { type: 'string', format: 'email' },
    product_id: { type: 'string', pattern: '^prod_[a-z0-9]{16}$' },
    quantity: { type: 'integer', minimum: 1, maximum: 100 },
  }
};

const validateOrder = ajv.compile(orderSchema);

router.post('/orders', (req, res) => {
  if (!validateOrder(req.body)) {
    return res.status(400).json({
      error: 'Validation failed',
      details: validateOrder.errors.map(e => ({
        field: e.instancePath,
        message: e.message,
      }))
    });
  }
  // Proceed with valid, typed data
});
```

**OpenAPI specification as contract:**

```yaml
# openapi.yaml — defines API contract including validation rules
openapi: 3.1.0
info:
  title: My API
  version: 1.0.0

paths:
  /orders:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateOrderRequest'
      responses:
        '201':
          description: Order created
        '400':
          $ref: '#/components/responses/ValidationError'

components:
  schemas:
    CreateOrderRequest:
      type: object
      required: [customer_email, product_id, quantity]
      additionalProperties: false
      properties:
        customer_email:
          type: string
          format: email
        product_id:
          type: string
          pattern: '^prod_[a-z0-9]{16}$'
        quantity:
          type: integer
          minimum: 1
          maximum: 100
```

### Defensive Measures

- **Validate on the server side always** — client-side validation is user experience, not security.
- **Use `additionalProperties: false`** in schemas to prevent mass assignment.
- **Fail closed:** Reject requests that don't match the schema. Don't try to "fix" invalid input.
- **Validate file uploads:** Check MIME type, file extension, and file content (magic bytes), not just filename.

```python
# Secure file upload validation
import magic  # python-magic library

ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'image/webp', 'application/pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def validate_upload(file_bytes: bytes, declared_filename: str) -> bool:
    # Check file size
    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError("File too large")
    
    # Check actual MIME type via magic bytes (not trusted extension/Content-Type)
    actual_mime = magic.from_buffer(file_bytes, mime=True)
    if actual_mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"File type not allowed: {actual_mime}")
    
    return True
```

### Practice Challenge

> Create an API endpoint that accepts a user profile update. Define a strict JSON Schema or Pydantic model. Attempt to send: oversized strings, HTML in name fields, extra fields (mass assignment), invalid email formats. Verify all are rejected with informative 400 responses.

---

## 4. Security Headers for APIs

### Beginner Explanation

HTTP security headers instruct browsers and clients how to handle your API responses. Proper headers prevent cross-site scripting, clickjacking, MIME sniffing, and information leakage.

### Technical Deep Dive

**Essential API security headers:**

```python
# FastAPI middleware — apply security headers to all API responses
from fastapi import Request
from fastapi.responses import Response

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # Prevent clickjacking (less relevant for pure APIs, important for any HTML)
    response.headers["X-Frame-Options"] = "DENY"
    
    # Enforce HTTPS
    response.headers["Strict-Transport-Security"] = \
        "max-age=31536000; includeSubDomains; preload"
    
    # Referrer policy — don't leak URL path in Referer header
    response.headers["Referrer-Policy"] = "no-referrer"
    
    # Permissions policy — disable browser features
    response.headers["Permissions-Policy"] = \
        "camera=(), microphone=(), geolocation=(), payment=()"
    
    # Cache control — prevent caching of sensitive API responses
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
    
    # Remove information-leaking headers
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    
    return response
```

**Content-Security-Policy for APIs that serve any HTML:**

```python
CSP_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none';"
)
response.headers["Content-Security-Policy"] = CSP_POLICY
```

**Header validation with securityheaders.com:**

```bash
# Check your API's headers
curl -I https://api.example.com/health | grep -i -E \
  "strict-transport|x-content-type|x-frame|content-security|referrer"
```

### Practice Challenge

> Audit the headers of a public API you use (or a test server you control). Identify any missing security headers. Implement the full header set above as middleware. Verify with `curl -I` and the Mozilla Observatory scanner.

---

## 5. CORS Policy

### Beginner Explanation

CORS (Cross-Origin Resource Sharing) controls which websites can make JavaScript requests to your API. Without proper CORS configuration, a malicious website could make API calls on behalf of your logged-in users.

### Technical Deep Dive

**How CORS works:**

```
Browser loads evil.com
evil.com JavaScript attempts:
  fetch('https://api.yourapp.com/account', {credentials: 'include'})

Browser sends preflight:
  OPTIONS /account HTTP/1.1
  Origin: https://evil.com
  Access-Control-Request-Method: GET

API server responds:
  Access-Control-Allow-Origin: https://yourapp.com  ← only your domain

Browser blocks the request — evil.com gets nothing
```

**Secure CORS configuration (FastAPI):**

```python
from fastapi.middleware.cors import CORSMiddleware

ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com",
]

# Development — extend only in dev
if os.environ.get("ENVIRONMENT") == "development":
    ALLOWED_ORIGINS.append("http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,           # explicit allowlist, never "*" with credentials
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    max_age=86400,                           # cache preflight for 24h
    expose_headers=["X-RateLimit-Remaining", "X-Request-ID"],
)
```

**Common CORS misconfigurations:**

```python
# ❌ DANGEROUS — wildcard with credentials (browsers block this, but still bad practice)
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# ❌ DANGEROUS — reflecting Origin header without validation
def get_cors_origin(request):
    return request.headers.get("Origin", "*")  # reflects ANY origin

# ❌ DANGEROUS — null origin (file:// pages, sandboxed iframes)
Access-Control-Allow-Origin: null

# ✅ SECURE — strict allowlist with exact matching
def get_cors_origin(request):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        return origin
    return None  # omit header if origin not in allowlist
```

**CORS for public APIs (no authentication):**

```nginx
# Public read-only API — wildcard is acceptable ONLY when no credentials
location /api/public/ {
    add_header Access-Control-Allow-Origin "*";
    add_header Access-Control-Allow-Methods "GET, OPTIONS";
    add_header Access-Control-Allow-Headers "Content-Type";
    # DO NOT add Access-Control-Allow-Credentials: true here
}
```

### Practice Challenge

> Create a simple API and a test HTML page on a different origin. Configure CORS to allow only your test page's origin. Verify that requests from a third origin are blocked by the browser. Attempt the `Origin: null` bypass and confirm it's blocked.

---

## 6. API Versioning and Deprecation Security

### Beginner Explanation

Old API versions are a major security risk. When you fix a vulnerability in v2 of your API but leave the vulnerable v1 running, attackers simply target v1. Proper versioning and deprecation policies close these windows.

### Technical Deep Dive

**Versioning strategies:**

```
URL versioning (most common):
  https://api.example.com/v1/users
  https://api.example.com/v2/users

Header versioning:
  GET /users HTTP/1.1
  Accept: application/vnd.example.v2+json

Both approaches valid; URL versioning is more explicit and easier to monitor.
```

**Deprecation headers:**

```python
# Signal deprecation to API consumers
from datetime import datetime

DEPRECATED_VERSIONS = {
    "v1": {
        "sunset_date": "2025-01-01",
        "successor": "/v2/",
        "deprecation_notice": "https://docs.example.com/api/migration-v1-v2"
    }
}

@app.middleware("http")
async def deprecation_warning(request: Request, call_next):
    response = await call_next(request)
    
    for version, info in DEPRECATED_VERSIONS.items():
        if f"/{version}/" in str(request.url):
            sunset = datetime.strptime(info["sunset_date"], "%Y-%m-%d")
            response.headers["Deprecation"] = "true"
            response.headers["Sunset"] = sunset.strftime("%a, %d %b %Y 00:00:00 GMT")
            response.headers["Link"] = (
                f'<{info["successor"]}>; rel="successor-version", '
                f'<{info["deprecation_notice"]}>; rel="deprecation"'
            )
    
    return response
```

**Shutting down deprecated versions safely:**

```python
# Phase 1: Add deprecation headers (3-6 months before sunset)
# Phase 2: Block new API key registrations for v1
# Phase 3: Return 410 Gone with migration instructions

@app.route('/v1/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def deprecated_v1(path):
    if datetime.utcnow() >= SUNSET_DATE:
        return jsonify({
            "error": "api_version_sunset",
            "message": "API v1 has been retired. Please migrate to v2.",
            "migration_guide": "https://docs.example.com/api/migration-v1-v2",
            "v2_endpoint": f"https://api.example.com/v2/{path}"
        }), 410
```

**Security implications of poor versioning:**

- Vulnerability fixed in v2 remains exploitable via v1
- v1 authentication controls (weaker) bypass v2 improvements
- Old endpoints may lack rate limiting, logging, or auth entirely

### Practice Challenge

> Add proper deprecation headers to a simulated v1 API. Implement a sunset date after which v1 returns 410. Verify that monitoring/alerting detects traffic still using deprecated endpoints.

---

## 7. Common API Attacks

### Beginner Explanation

APIs face a distinct set of attacks compared to traditional web pages. This section covers the most impactful: BOLA (accessing other users' objects), mass assignment (overwriting internal fields), and excessive data exposure (returning more data than needed).

### Technical Deep Dive

#### BOLA — Broken Object-Level Authorization

```python
# ❌ VULNERABLE — no ownership check
@router.get("/api/v1/orders/{order_id}")
def get_order(order_id: str, current_user = Depends(get_current_user)):
    order = db.orders.find_one({"_id": order_id})
    if not order:
        raise HTTPException(404)
    return order   # Returns ANY user's order if they guess/enumerate the ID

# ✅ SECURE — enforce object ownership
@router.get("/api/v1/orders/{order_id}")
def get_order(order_id: str, current_user = Depends(get_current_user)):
    order = db.orders.find_one({
        "_id": order_id,
        "customer_id": current_user.id   # ownership enforced at DB level
    })
    if not order:
        raise HTTPException(404)   # same response for not-found and unauthorized
    return order
```

#### Mass Assignment

```python
# ❌ VULNERABLE — directly assigning request body to model
@router.put("/users/me")
def update_profile(updates: dict, current_user = Depends(get_current_user)):
    current_user.update(**updates)  # Attacker sends: {"role": "admin", "verified": true}
    db.commit()

# ✅ SECURE — explicit allowlist of mutable fields
class ProfileUpdateRequest(BaseModel):
    display_name: Optional[str] = Field(None, max_length=100)
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[HttpUrl] = None
    # Note: role, verified, account_balance are NOT included
    
    class Config:
        extra = 'forbid'   # Pydantic rejects any extra fields

@router.put("/users/me")
def update_profile(updates: ProfileUpdateRequest, current_user = Depends(get_current_user)):
    # Only the safe fields defined in ProfileUpdateRequest can be updated
    current_user.display_name = updates.display_name or current_user.display_name
    current_user.bio = updates.bio or current_user.bio
    db.commit()
```

#### Excessive Data Exposure

```python
# ❌ VULNERABLE — returning full DB model
class User(Base):
    id = Column(UUID)
    email = Column(String)
    password_hash = Column(String)    # ❌ exposed
    internal_score = Column(Float)   # ❌ exposed
    admin_notes = Column(Text)       # ❌ exposed
    stripe_customer_id = Column(String)  # ❌ exposed

@router.get("/users/{user_id}")
def get_user(user_id: str):
    return db.query(User).get(user_id).__dict__  # dumps EVERYTHING

# ✅ SECURE — explicit response model
from pydantic import BaseModel

class PublicUserResponse(BaseModel):
    id: str
    display_name: str
    avatar_url: Optional[str]
    created_at: datetime
    # Only public-safe fields

@router.get("/users/{user_id}", response_model=PublicUserResponse)
def get_user(user_id: str):
    user = db.query(User).get(user_id)
    return user  # FastAPI serializes only PublicUserResponse fields
```

### Real-World Relevance

- **Venmo (2019):** The public API returned full transaction history including names and notes. A researcher scraped 207 million public transactions to map financial relationships between users.
- **Peloton (2021):** Unauthenticated BOLA allowed anyone to retrieve any user's private profile data including age, weight, and workout history by incrementing user IDs.
- **GitHub (2022):** A bug in the npm registry API allowed package metadata to be modified via mass assignment of properties that should be server-controlled.

### Defensive Measures

- **BOLA:** Always filter by `owner_id = current_user.id` at the database level.
- **Mass assignment:** Define explicit input schemas with only mutable fields; use `extra = 'forbid'`.
- **Excessive data exposure:** Define explicit response schemas; never return raw ORM objects.
- **Test all three:** Include BOLA, mass assignment, and exposure tests in your API test suite.

### Practice Challenge

> Build an API with user profiles and orders. Write test cases that: (1) verify user A cannot read user B's orders, (2) verify sending `{"role": "admin"}` in a profile update is rejected with 422, (3) verify the user response schema does not include `password_hash` or internal fields.

---

## 8. OWASP API Security Top 10

The OWASP API Security Top 10 (2023) addresses API-specific risks distinct from the web application Top 10.

| # | Risk | Description | Key Control |
|---|------|-------------|-------------|
| **API1** | Broken Object Level Authorization | BOLA/IDOR — accessing other users' objects | Ownership check on every object query |
| **API2** | Broken Authentication | Weak auth mechanisms, missing MFA | Strong auth, short-lived tokens |
| **API3** | Broken Object Property Level Authorization | Mass assignment + excessive data exposure | Input allowlists, response schemas |
| **API4** | Unrestricted Resource Consumption | No rate limiting on expensive operations | Rate limiting, pagination limits |
| **API5** | Broken Function Level Authorization | Accessing admin functions as regular user | Role-based endpoint authorization |
| **API6** | Unrestricted Access to Sensitive Business Flows | Abusing business logic (bulk purchases, coupon abuse) | Business logic rate limits and fraud detection |
| **API7** | Server-Side Request Forgery | Tricking server to fetch internal resources | URL allowlisting, egress filtering |
| **API8** | Security Misconfiguration | Default configs, verbose errors, missing TLS | Hardened defaults, suppress errors |
| **API9** | Improper Inventory Management | Forgotten deprecated/debug APIs | API gateway with full inventory |
| **API10** | Unsafe Consumption of APIs | Trusting 3rd-party API responses without validation | Validate and sanitize all external API data |

**API10 — Unsafe consumption of external APIs:**

```python
# ❌ VULNERABLE — trusting external API response blindly
def get_user_info(external_user_id: str):
    response = requests.get(f"https://partner-api.example.com/users/{external_user_id}")
    data = response.json()
    return {"name": data["name"], "role": data["role"]}  # directly using external data

# ✅ SECURE — validate external API responses with a schema
class ExternalUserResponse(BaseModel):
    name: str = Field(..., max_length=100)
    email: EmailStr
    # 'role' is NOT accepted from external API — we determine role internally
    
    class Config:
        extra = 'ignore'  # ignore unexpected fields from external source

def get_user_info(external_user_id: str):
    response = requests.get(
        f"https://partner-api.example.com/users/{external_user_id}",
        timeout=5
    )
    response.raise_for_status()
    
    validated = ExternalUserResponse.parse_obj(response.json())
    # Determine role from internal logic, not from external API
    internal_role = determine_role(validated.email)
    return {"name": validated.name, "role": internal_role}
```

### Practice Challenge

> Review a public-facing API specification (your own or an open-source project's). Map each endpoint to the OWASP API Top 10. Identify at least one finding per category that applies or could apply. Propose a concrete mitigation for each.

---

## 📋 API Security Checklist

```
Authentication
  [ ] OAuth 2.0 with PKCE for user auth
  [ ] API keys hashed in storage, scoped to minimum permissions
  [ ] JWT: explicit algorithm allowlist, required claims, short expiry
  [ ] Refresh token rotation on use

Authorization
  [ ] Object-level authorization on every endpoint
  [ ] Role-based function-level authorization
  [ ] Input schemas block mass assignment (additionalProperties: false)
  [ ] Response schemas prevent excessive data exposure

Transport & Headers
  [ ] TLS 1.3 enforced
  [ ] HSTS with preload
  [ ] X-Content-Type-Options: nosniff
  [ ] CORS: explicit origin allowlist, no wildcard with credentials
  [ ] Cache-Control: no-store on sensitive endpoints

Rate Limiting
  [ ] Login endpoint: 5-10 requests/minute/IP
  [ ] Registration: 3-10 requests/hour/IP
  [ ] General API: appropriate limit with 429 + Retry-After

Validation
  [ ] Server-side schema validation on all inputs
  [ ] File uploads: MIME type, size, magic bytes
  [ ] Parameterized queries (no string concatenation in DB queries)

Versioning
  [ ] Deprecation headers on old versions
  [ ] Sunset date enforced
  [ ] Traffic monitoring for deprecated version usage

Monitoring
  [ ] All auth events logged (success + failure)
  [ ] Authorization failures logged
  [ ] Rate limit breaches logged and alerted
  [ ] Anomalous data access patterns trigger alerts
```

---

*Part of the [CyberPath Defensive Security Roadmap](../README.md)*
