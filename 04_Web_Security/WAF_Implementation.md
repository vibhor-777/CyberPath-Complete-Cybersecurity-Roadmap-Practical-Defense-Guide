# WAF Implementation Guide

> **Module:** [04 Web Security](./README.md) | **Back to root:** [Repository Root](../README.md)

A Web Application Firewall (WAF) is a critical layer of defense-in-depth for web applications. This guide covers what WAFs do, how to configure and tune them effectively, and how to monitor WAF activity—approaching bypass techniques only as context for defensive tuning.

---

## Table of Contents

1. [What a WAF Does and Doesn't Do](#1-what-a-waf-does-and-doesnt-do)
2. [ModSecurity with OWASP Core Rule Set](#2-modsecurity-with-owasp-core-rule-set)
3. [Cloudflare WAF Configuration](#3-cloudflare-waf-configuration)
4. [Tuning Rules to Reduce False Positives](#4-tuning-rules-to-reduce-false-positives)
5. [Bypass Awareness for Defensive Tuning](#5-bypass-awareness-for-defensive-tuning)
6. [Monitoring WAF Logs](#6-monitoring-waf-logs)

---

## 1. What a WAF Does and Doesn't Do

### Beginner Explanation

A WAF sits between the internet and your web application, inspecting every HTTP request and response. Think of it as a security guard that reads all incoming mail looking for suspicious content—it can stop many common attacks before they reach your application code.

### What a WAF Does

| Capability | Description |
|------------|-------------|
| **Signature matching** | Blocks known attack payloads (SQLi, XSS, command injection patterns) |
| **Protocol enforcement** | Rejects malformed HTTP requests |
| **Rate limiting** | Limits requests per IP/session |
| **Geo-blocking** | Blocks traffic from specific countries/regions |
| **IP reputation** | Blocks known-malicious IP addresses |
| **Virtual patching** | Temporarily mitigates vulnerabilities before a code fix is deployed |
| **DDoS L7 mitigation** | Absorbs application-layer DDoS traffic |
| **Bot management** | Distinguishes legitimate bots from malicious crawlers |

### What a WAF Does NOT Do

| Limitation | Explanation |
|-----------|-------------|
| **Not a substitute for secure code** | A WAF can be bypassed; the app must also be secure |
| **Can't decrypt end-to-end** | If traffic is encrypted app-side, WAF can't inspect it without terminating TLS |
| **Business logic attacks** | Rules can't know your app's business context |
| **Zero-day exploits** | Novel attacks may have no signatures |
| **Client-side attacks** | XSS executing in victim's browser bypasses server-side WAF |
| **Authenticated user abuse** | Actions by legitimate users look valid to a WAF |

### Defense-in-Depth Position

```
Internet ──► CDN/DDoS Protection ──► WAF ──► Load Balancer ──► App Server ──► Database
                                       │
                                 Blocks known
                                 attack patterns
                                 (defense layer 2 of many)
```

> **Key Principle:** A WAF is defense-in-depth—layer 2 or 3 in a multi-layered strategy. Parameterized queries, input validation, and RBAC in your code are layers 1. The WAF catches what slips through or is deployed before a code fix is ready.

### Real-World Relevance

- **Capital One (2019):** Had a WAF deployed but it was misconfigured, allowing SSRF. The WAF was not the root cause of the breach but illustrates that deployment alone is insufficient—proper configuration and monitoring are essential.
- **Magecart attacks (ongoing):** JavaScript skimmers in CDN-loaded libraries are injected into pages. A WAF cannot detect client-side attacks happening in the visitor's browser.

---

## 2. ModSecurity with OWASP Core Rule Set

### Beginner Explanation

ModSecurity is an open-source WAF engine that runs as an Apache, Nginx, or IIS module. The OWASP Core Rule Set (CRS) is a generic attack detection rule set for ModSecurity that covers the OWASP Top 10 and more.

### Technical Deep Dive

**Installation on Ubuntu with Nginx:**

```bash
# Install ModSecurity and Nginx connector
sudo apt update
sudo apt install -y libmodsecurity3 libmodsecurity-dev nginx

# Install Nginx ModSecurity connector
sudo apt install -y libnginx-mod-http-modsecurity

# Download OWASP CRS
cd /etc/nginx
sudo git clone https://github.com/coreruleset/coreruleset.git /etc/nginx/owasp-crs
sudo cp /etc/nginx/owasp-crs/crs-setup.conf.example /etc/nginx/owasp-crs/crs-setup.conf

# Download ModSecurity default config
sudo wget -O /etc/nginx/modsecurity.conf \
  https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
```

**ModSecurity core configuration (`/etc/nginx/modsecurity.conf`):**

```apache
# Engine mode
# DetectionOnly — logs but does not block (start here for new deployments)
# On             — actively blocks matching requests
SecRuleEngine DetectionOnly   # change to "On" after tuning

# Request body inspection
SecRequestBodyAccess On
SecRequestBodyLimit 13107200           # 12.5 MB max request body
SecRequestBodyNoFilesLimit 131072      # 128 KB for non-file request bodies
SecRequestBodyInMemoryLimit 131072

# Response body inspection (use judiciously — performance impact)
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 524288            # 512 KB

# Temporary files and upload handling
SecTmpDir /tmp/
SecDataDir /tmp/

# Audit logging
SecAuditEngine RelevantOnly           # log only relevant events
SecAuditLogRelevantStatus "^(?:5|4(?!04))"  # log 4xx (except 404) and 5xx
SecAuditLog /var/log/nginx/modsec_audit.log
SecAuditLogFormat JSON                # JSON format for SIEM ingestion
SecAuditLogParts ABIJDEFHZ

# Debug logging (disable in production)
SecDebugLog /var/log/nginx/modsec_debug.log
SecDebugLogLevel 0   # 0=off, 9=maximum

# Default actions
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
```

**CRS setup configuration (`/etc/nginx/owasp-crs/crs-setup.conf`):**

```apache
# Paranoia level — controls rule aggressiveness
# PL1: Default — low false positives, good coverage
# PL2: More rules, more false positives, better coverage
# PL3: Aggressive — many false positives, for high-security apps
# PL4: Maximum — expect many false positives, tune carefully
SecAction \
  "id:900000,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.paranoia_level=1"

# Anomaly scoring thresholds
# Requests exceeding inbound threshold are blocked
SecAction \
  "id:900110,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.inbound_anomaly_score_threshold=5,\
   setvar:tx.outbound_anomaly_score_threshold=4"

# Sampling mode (for production rollout)
# Block only X% of matching requests during initial deployment
SecAction \
  "id:900400,\
   phase:1,\
   pass,\
   nolog,\
   setvar:tx.sampling_rnd100=@random"

# HTTP methods allowlist
SecAction \
  "id:900200,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:'tx.allowed_methods=GET HEAD POST PUT DELETE PATCH OPTIONS'"

# Content-Type allowlist
SecAction \
  "id:900220,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/json-patch+json|'"
```

**Nginx configuration to load ModSecurity + CRS:**

```nginx
# /etc/nginx/nginx.conf
http {
    # Load ModSecurity module
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec_includes.conf;
    
    server {
        listen 443 ssl http2;
        server_name app.example.com;
        
        # SSL configuration
        ssl_certificate /etc/ssl/certs/app.crt;
        ssl_certificate_key /etc/ssl/private/app.key;
        ssl_protocols TLSv1.3;
        
        location / {
            proxy_pass http://backend:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
```

```apache
# /etc/nginx/modsec_includes.conf
Include /etc/nginx/modsecurity.conf
Include /etc/nginx/owasp-crs/crs-setup.conf
Include /etc/nginx/owasp-crs/rules/*.conf
# Custom rules AFTER CRS rules
Include /etc/nginx/modsecurity_custom_rules.conf
```

**Custom blocking rules:**

```apache
# /etc/nginx/modsecurity_custom_rules.conf

# Block requests with suspicious User-Agent strings
SecRule REQUEST_HEADERS:User-Agent "@rx (sqlmap|nikto|nessus|openvas|masscan)" \
  "id:10001,\
   phase:1,\
   deny,\
   status:403,\
   log,\
   msg:'Blocked scanner User-Agent'"

# Block path traversal attempts
SecRule REQUEST_URI "@contains ../" \
  "id:10002,\
   phase:1,\
   deny,\
   status:400,\
   log,\
   msg:'Path traversal attempt'"

# Block access to sensitive files
SecRule REQUEST_URI "@rx \.(git|env|htpasswd|htaccess|bak|backup|sql|conf|config)$" \
  "id:10003,\
   phase:1,\
   deny,\
   status:404,\
   log,\
   msg:'Access to sensitive file extension blocked'"

# SSRF protection — block metadata endpoint references in parameters
SecRule ARGS|REQUEST_HEADERS "@rx 169\.254\.169\.254" \
  "id:10004,\
   phase:2,\
   deny,\
   status:400,\
   log,\
   msg:'Potential SSRF - cloud metadata IP in request'"
```

### Practice Challenge

> ⚠️ **Lab Environment Only** — Deploy Nginx + ModSecurity + CRS in a Docker container. Set `SecRuleEngine DetectionOnly`. Run OWASP ZAP against your test application. Review the audit log to see which attacks CRS detected. Then switch to `SecRuleEngine On` and verify attacks are blocked.

---

## 3. Cloudflare WAF Configuration

### Beginner Explanation

Cloudflare WAF is a managed cloud-based WAF service. It provides automatic rule updates from Cloudflare's threat intelligence, without requiring you to manage a WAF server. It's particularly suitable for organizations that want WAF protection without dedicated infrastructure.

### Technical Deep Dive

**Cloudflare WAF rule types:**

| Rule Type | Description | Management |
|-----------|-------------|-----------|
| Managed Rules | Cloudflare-maintained rules (OWASP + proprietary) | Automatic updates |
| Custom Rules | Your own match conditions and actions | Manual |
| Rate Limiting Rules | Request-rate-based blocking | Manual |
| Bot Management | Browser integrity checks, bot scoring | Managed + Custom |

**Enabling OWASP-based managed rules via Cloudflare API:**

```bash
# Enable Cloudflare-managed OWASP rulesets
# (Alternatively configure via dashboard: Security → WAF → Managed rules)

ZONE_ID="your_zone_id"
CF_API_TOKEN="your_api_token"

# List available managed rulesets
curl -X GET \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json"

# Enable Cloudflare Managed Ruleset
curl -X PUT \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_request_firewall_managed/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rules": [
      {
        "action": "execute",
        "expression": "true",
        "action_parameters": {
          "id": "efb7b8c949ac4650a09736fc376e9aee",
          "overrides": {
            "sensitivity_level": "medium"
          }
        }
      }
    ]
  }'
```

**Custom WAF rules (Cloudflare Ruleset Engine expression language):**

```
# Block SQLi patterns in query strings
(http.request.uri.query contains "' OR '" or 
 http.request.uri.query contains "UNION SELECT" or
 http.request.uri.query matches r"(?i)(\bor\b|\band\b)\s+\d+=\d+")

# Block scanner User-Agents
(http.user_agent contains "sqlmap" or 
 http.user_agent contains "nikto" or
 http.user_agent contains "nessus")

# Rate limit login endpoint
(http.request.uri.path eq "/api/auth/login" and
 http.request.method eq "POST")
→ Action: Rate limit 10 requests per minute per IP

# Block traffic from high-risk countries (tailor to your risk model)
(ip.geoip.country in {"XX" "YY"} and 
 not ip.geoip.asnum in {15169 8075})  # allow Google and Microsoft IPs
→ Action: Challenge (CAPTCHA)

# Protect admin panel — allow only corporate IP range
(http.request.uri.path starts_with "/admin" and
 not ip.src in {203.0.113.0/24})
→ Action: Block
```

**Cloudflare WAF sensitivity levels:**

```
Low sensitivity:    PL1 rules — minimal false positives
Medium sensitivity: PL2 rules — balanced (recommended for most sites)
High sensitivity:   PL3 rules — may require tuning
```

**Rate limiting rule configuration:**

```json
{
  "description": "Protect login endpoint from brute force",
  "expression": "(http.request.uri.path eq \"/api/auth/login\")",
  "action": "block",
  "ratelimit": {
    "characteristics": ["ip.src"],
    "period": 60,
    "requests_per_period": 5,
    "mitigation_timeout": 300
  }
}
```

### Practice Challenge

> If you have a Cloudflare-proxied domain, enable the Cloudflare Managed OWASP ruleset. Use the Cloudflare Firewall Events dashboard to review triggered events. Create a custom rule to block a specific bad User-Agent string and verify it works.

---

## 4. Tuning Rules to Reduce False Positives

### Beginner Explanation

Every legitimate request that gets blocked by the WAF is a false positive—a real user turned away. Poorly tuned WAFs cause business disruption and tempt teams to disable WAF rules entirely. Proper tuning reduces false positives while maintaining protection.

### Technical Deep Dive

**Tuning workflow:**

```
1. Deploy in Detection-Only mode
2. Run for 2-4 weeks collecting audit logs
3. Identify the most frequent false positive rules
4. For each rule: understand WHY it fires on legitimate traffic
5. Create targeted exclusions (never disable the entire rule)
6. Re-validate: does the exclusion break the rule's protection?
7. Switch to Blocking mode
8. Monitor false positives continuously
```

**Analyzing CRS audit logs for false positives:**

```bash
# Find most frequently triggered rules
grep "id \"" /var/log/nginx/modsec_audit.log | \
  grep -oP 'id "\K[0-9]+' | sort | uniq -c | sort -rn | head 20

# See what triggered a specific rule
grep "942100" /var/log/nginx/modsec_audit.log | \
  python3 -c "import sys, json; [print(json.dumps(json.loads(l), indent=2)) for l in sys.stdin]" | \
  grep -A5 -B5 "matchedData"
```

**ModSecurity rule exclusions (targeted approach):**

```apache
# Approach 1: Disable rule for specific URI only
# CRS rule 942100 (SQL Injection) fires on /api/search endpoint
# because the GraphQL query syntax looks like SQL
SecRuleUpdateTargetById 942100 "!REQUEST_URI:/api/graphql"

# Approach 2: Exclude specific parameter from a specific rule
# Rule 942200 fires on 'description' field containing colons
SecRuleUpdateTargetById 942200 "!ARGS:description"

# Approach 3: Disable rule entirely for specific IP (admin users)
SecRule REMOTE_ADDR "@ipMatch 10.0.1.100" \
  "id:20001,phase:1,pass,nolog,ctl:ruleRemoveById=942100-942999"

# Approach 4: Raise anomaly threshold for specific path
SecRule REQUEST_URI "@beginsWith /api/admin/" \
  "id:20002,phase:1,pass,nolog,ctl:ruleRemoveTargetById=949110;ARGS:complex_json_payload"
```

**CRS exclusion packages (pre-built for common apps):**

```apache
# CRS ships exclusion packages for popular applications
# Load BEFORE CRS rules
Include /etc/nginx/owasp-crs/plugins/wordpress-exclusion-before.conf

# Load AFTER CRS rules  
Include /etc/nginx/owasp-crs/plugins/wordpress-exclusion-after.conf

# Available for: WordPress, Drupal, Nextcloud, phpMyAdmin, XenForo, etc.
```

**Anomaly scoring — understand before blocking:**

```apache
# CRS uses anomaly scoring: rules add scores, threshold triggers block
# Default: inbound threshold = 5

# Common rule scores:
# Critical (SQLi, XSS): +5 → immediate block at default threshold
# Error (protocol violations): +4
# Warning: +3
# Notice: +2

# If a legitimate request scores 4 (warning level), raising threshold to 8
# allows it through while still blocking Critical-scored attacks
SecAction \
  "id:900110,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.inbound_anomaly_score_threshold=8"  # raised from 5

# Better approach: fix the specific rule causing the false positive
```

**Testing exclusions don't break protection:**

```bash
# After adding an exclusion, verify the attack is still blocked
# Use a controlled test payload (lab environment only)

# Test SQLi detection still works on non-excluded parameter
curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost/api/search?q=1%27+OR+%271%27%3D%271" 
# Expected: 403

# Verify legitimate request on the previously false-positive parameter now works
curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost/api/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { id name } }"}'
# Expected: 200
```

### Real-World Considerations

**False positive risk taxonomy:**

| Source | Example | Solution |
|--------|---------|---------|
| Rich text editors | HTML in blog post body | Exclude ARGS:body from XSS rules in editor endpoints |
| File uploads | Binary content in multipart | Exclude `FILES` target from content-inspection rules |
| API payloads | Complex JSON with special chars | Schema-validate in app; narrow WAF rules |
| Legitimate software | Specific User-Agent strings | Allowlist known-good UAs |
| Internal services | Scanner/crawler for monitoring | Allowlist internal IPs |

### Practice Challenge

> Enable CRS on a WordPress or static blog site. Identify the top 5 false-positive rules from audit logs. Apply targeted exclusions for each using `SecRuleUpdateTargetById`. Verify: legitimate functionality restored AND a corresponding SQLi/XSS test payload is still blocked.

---

## 5. Bypass Awareness for Defensive Tuning

> ⚠️ **Defensive Context Only** — The techniques described here are documented to help defenders understand *why* certain WAF configurations are insufficient and what additional controls are needed. Attempting to bypass WAFs on systems you do not own and have not explicitly authorized is illegal.

### Beginner Explanation

Attackers attempt to craft malicious payloads that avoid matching WAF signatures. Understanding the *categories* of bypass techniques helps defenders write better rules, validate their WAF configurations, and understand the inherent limitations of WAF-only security.

### Technical Deep Dive

**Why WAF bypass awareness matters defensively:**

1. It reveals that WAFs are not a standalone solution—application-level controls are essential.
2. It informs what to look for in WAF logs (encoded or obfuscated payloads).
3. It guides rule testing: if your test payload looks exactly like textbook SQLi, you're only testing the obvious case.

**Category 1: Encoding and obfuscation**

WAFs matching literal strings can be evaded by encoding. Defenders should ensure their WAF engine decodes before inspecting:

```apache
# ModSecurity — enable transformations to normalize before matching
SecRule ARGS "@detectSQLi" \
  "id:942001,\
   phase:2,\
   deny,\
   t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,\
   msg:'SQL Injection Attempt (transformed)'"
  
# The transformation chain:
# 1. utf8toUnicode    — normalize unicode representations
# 2. urlDecodeUni     — decode URL encoding (%27 → ')
# 3. htmlEntityDecode — decode HTML entities (&quot; → ")
# 4. lowercase        — case-normalization
```

**Category 2: HTTP protocol variations**

WAFs must handle all valid (and some invalid) HTTP variants:

```apache
# ModSecurity — enforce HTTP standard compliance
SecRule REQUEST_HEADERS:Content-Type "!@within |application/x-www-form-urlencoded| |multipart/form-data| |application/json| |text/xml|" \
  "id:920420,phase:1,deny,status:415,msg:'Request content type is not allowed'"

# Limit HTTP methods to only those the application uses
SecRule REQUEST_METHOD "!@within GET POST PUT DELETE PATCH OPTIONS HEAD" \
  "id:911100,phase:1,deny,status:405,msg:'HTTP method not allowed'"
```

**Category 3: Chunked/multipart request bodies**

```apache
# Ensure request body is fully inspected, not just the first chunk
SecRequestBodyAccess On
SecRequestBodyLimit 13107200

# Reject requests claiming multipart but with malformed boundary
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
  "id:200003,phase:2,deny,status:400,msg:'Multipart request body failed strict validation'"
```

**Defensive validation pipeline:**

The correct approach when a WAF bypass is possible is to ensure the application itself is secure:

```
WAF (pattern matching) → Application (parameterized queries + input validation)
     ↓                            ↓
 Catches ~80-90%              Catches 100%
 of known patterns            of injection
 (encoded or not)             (regardless of encoding)
```

**Testing your WAF with GoTestWAF:**

```bash
# ⚠️ Lab environment only — test against your own WAF
docker run --network host \
  wallarm/gotestwaf:latest \
  --url=http://localhost:80 \
  --noEmailReport

# GoTestWAF sends ~200 test payloads across different categories
# and reports what percentage the WAF blocks vs misses
```

### Defensive Measures

- **Layer security:** WAF is not the last line of defense. Parameterized queries block SQLi regardless of encoding.
- **Enable all CRS transformations:** Normalize input before matching.
- **Monitor for encoded payloads:** Unusual encoding in query strings (excessive `%XX`) can indicate evasion attempts.
- **Test regularly:** Use GoTestWAF or custom tests quarterly to verify WAF effectiveness.
- **Keep CRS updated:** `git pull` the OWASP CRS repository regularly; new signatures are added frequently.

---

## 6. Monitoring WAF Logs

### Beginner Explanation

A WAF that isn't monitored is security theater. Logs tell you who is attacking, what they're targeting, whether your rules are working, and whether false positives are affecting legitimate users.

### Technical Deep Dive

**ModSecurity JSON audit log structure:**

```json
{
  "transaction": {
    "time": "2024-01-15T14:23:45.123456Z",
    "transaction_id": "Yqa0kc8AAAEAAHjU3wAAAAX",
    "remote_address": "203.0.113.45",
    "remote_port": "54321",
    "local_address": "10.0.0.10",
    "local_port": "443"
  },
  "request": {
    "method": "POST",
    "uri": "/api/login",
    "http_version": "HTTP/2.0",
    "headers": {
      "Host": "app.example.com",
      "User-Agent": "Mozilla/5.0 ..."
    },
    "body": "username=admin&password=..."
  },
  "response": {
    "status": 403,
    "headers": {}
  },
  "audit_data": {
    "stopwatch": "1705325025123456 1234 (- - -)",
    "stopwatch2": "1705325025123456 1234; combined=0, p1=0, p2=1234, p3=0, p4=0, p5=0",
    "producer": ["ModSecurity for nginx (NGINX)/1.0.3"],
    "server": "nginx",
    "messages": [
      {
        "message": "Warning. Pattern match ...",
        "details": {
          "match": "Matched Data: ' OR found within ARGS:username",
          "reference": "o0,5v12,30",
          "ruleId": "942100",
          "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
          "lineNumber": "65",
          "data": "Matched Data: ' OR ...",
          "severity": "CRITICAL",
          "ver": "OWASP_CRS/4.0.0",
          "maturity": "9",
          "accuracy": "8",
          "tags": ["application-multi", "language-multi", "attack-sqli", "OWASP_CRS"],
          "hostname": "app.example.com",
          "uri": "/api/login",
          "uniqueId": "Yqa0kc8AAAEAAHjU3wAAAAX"
        }
      }
    ]
  }
}
```

**Shipping WAF logs to Elasticsearch:**

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/nginx/modsec_audit.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_type: modsecurity_waf
    fields_under_root: true

processors:
  - decode_json_fields:
      fields: ["message"]
      target: "parsed"
      overwrite_keys: true

output.elasticsearch:
  hosts: ["https://elasticsearch.internal:9200"]
  index: "waf-logs-%{+yyyy.MM.dd}"
  ssl.certificate_authorities: ["/etc/ssl/certs/ca.crt"]
  username: "${ELASTIC_USER}"
  password: "${ELASTIC_PASS}"
```

**Kibana dashboards to build:**

| Dashboard | Visualizations |
|-----------|---------------|
| Attack Overview | Events/hour by rule ID, Top attacking IPs, Top targeted URIs |
| Geo Map | Attack origin countries |
| Rule Distribution | Pie chart: SQLi vs XSS vs RFI vs scanning |
| False Positive Monitor | 403s followed by user complaints; legitimate user IPs in block list |
| Trend Analysis | Attack volume over time, spike detection |

**Splunk queries for WAF monitoring:**

```spl
# Attack volume by rule ID — top 10
index=waf sourcetype=modsecurity
| rex field=_raw "ruleId\":\"(?P<rule_id>\d+)\""
| stats count by rule_id
| sort -count | head 10

# Brute force detection — IPs with >50 WAF events in 1 hour
index=waf sourcetype=modsecurity
| bucket _time span=1h
| stats count by src_ip _time
| where count > 50
| sort -count

# New attacking IPs in last 24h (not seen in prior 7 days)
index=waf sourcetype=modsecurity earliest=-24h
| stats count by src_ip
| join type=left [
    search index=waf sourcetype=modsecurity earliest=-7d latest=-24h
    | stats count by src_ip
    | rename src_ip as src_ip_old
  ]
| where isnull(count_old)
| sort -count
```

**Alerting rules:**

```yaml
# Prometheus alerting for WAF metrics (via modsecurity-exporter)
groups:
  - name: waf_alerts
    rules:
      - alert: WAFHighBlockRate
        expr: rate(modsecurity_blocked_requests_total[5m]) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "WAF blocking >100 requests/5min"
          description: "Possible attack wave or false positive storm"

      - alert: WAFTopAttackingIP
        expr: modsecurity_blocks_by_ip > 500
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Single IP responsible for >500 WAF blocks"
```

**Key metrics to track:**

| Metric | Baseline | Alert Threshold |
|--------|----------|-----------------|
| Blocks/minute | Establish 2-week baseline | >3σ from baseline |
| Unique attacking IPs/day | Baseline | >50% increase |
| False positive rate | <1% of legitimate traffic | >2% |
| Top rule trigger counts | Baseline | Any new rule in top 5 |
| Block→bypass ratio | Monitoring only | Track over time |

**WAF log retention:**

```
Real-time alerting:   Immediate
Online searchable:    90 days minimum
Cold storage:         1 year minimum
Compliance (PCI DSS): 12 months, 3 months readily available
```

### Practice Challenge

> Set up Filebeat to ship ModSecurity JSON audit logs to Elasticsearch. Create a Kibana dashboard showing: (1) attacks blocked per hour, (2) top 10 rule IDs triggered, (3) top 10 source IPs by block count, (4) geographic map of attack origins. Set up an email alert when block rate exceeds 50/minute.

---

## 📋 WAF Implementation Checklist

```
Initial Deployment
  [ ] Deploy in DetectionOnly mode for 2-4 weeks
  [ ] Baseline normal traffic patterns
  [ ] Review audit logs daily during detection phase
  [ ] Identify and document false positives

Rule Configuration
  [ ] OWASP CRS installed and updated
  [ ] Paranoia Level set appropriately for application risk
  [ ] Anomaly scoring thresholds configured
  [ ] Custom rules for application-specific threats
  [ ] HTTP method allowlist (only GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
  [ ] File extension blocklist (.env, .git, .bak, .sql)

Tuning
  [ ] Targeted exclusions for false positives (not disabling entire rules)
  [ ] CRS exclusion packages loaded for known CMS/frameworks
  [ ] Admin interfaces excluded from certain rules or IP-restricted
  [ ] Tested: attack payloads still blocked after tuning

Production Blocking
  [ ] SecRuleEngine set to On
  [ ] Block response returns helpful 403 page (no debug info)
  [ ] Rate limiting rules active on auth endpoints

Monitoring
  [ ] Logs shipped to central SIEM (Elasticsearch/Splunk)
  [ ] Dashboard: attacks/hour, top IPs, top rules
  [ ] Alert: >50 blocks/minute from single IP
  [ ] Alert: block rate 3σ above baseline
  [ ] Log retention: 90 days online, 1 year cold

Maintenance
  [ ] CRS version pinned, update tested in staging before production
  [ ] Monthly review of top false positives
  [ ] Quarterly WAF effectiveness test (GoTestWAF)
  [ ] Annual penetration test includes WAF bypass assessment
```

---

*Part of the [CyberPath Defensive Security Roadmap](../README.md)*
