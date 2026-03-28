# Protocols Deep Dive — DNS, DHCP, HTTP/S, and TCP/IP

## DNS — Domain Name System

### How DNS Works

DNS translates human-readable hostnames into IP addresses. It operates on **UDP port 53** (and TCP for zone transfers or large responses).

```
User types: www.example.com
     │
     ▼
Recursive Resolver (ISP or 8.8.8.8)
     │ Cache miss
     ▼
Root Name Server (.)
     │ Referral to .com TLD
     ▼
TLD Name Server (.com)
     │ Referral to example.com
     ▼
Authoritative Name Server (example.com)
     │ Returns: 93.184.216.34
     ▼
Answer returned to client → cached
```

### DNS Record Types

| Record | Purpose | Security Relevance |
|--------|---------|-------------------|
| A | Maps hostname → IPv4 | Can be hijacked to redirect traffic |
| AAAA | Maps hostname → IPv6 | Same risks as A records |
| CNAME | Alias to another hostname | Subdomain takeover risk |
| MX | Mail server | Spoofing if SPF/DKIM absent |
| TXT | Arbitrary text | Houses SPF, DKIM, DMARC records |
| NS | Authoritative nameservers | If compromised, allows full hijacking |
| SOA | Zone authority info | Information disclosure |
| PTR | Reverse DNS lookup | Used in spam filtering |

### DNS Security Controls

```bash
# Check DNSSEC status for a domain
dig +dnssec example.com

# Verify SPF record (anti-spoofing)
dig TXT example.com | grep spf

# Verify DMARC record (email authentication policy)
dig TXT _dmarc.example.com

# Check for DNS zone transfer (should be denied from non-authorized sources)
dig axfr @ns1.example.com example.com
# If this returns zone data, the server is MISCONFIGURED
```

### DNS Hardening Checklist

- [ ] Enable **DNSSEC** on all authoritative zones
- [ ] Restrict **zone transfers** to authorized secondary servers only
- [ ] Use **DNS-over-HTTPS (DoH)** or **DNS-over-TLS (DoT)** for recursive queries
- [ ] Monitor for **DNS tunneling** (unusually long queries, high-entropy subdomains)
- [ ] Configure **Response Policy Zones (RPZ)** to block known malicious domains
- [ ] Implement **DMARC, DKIM, and SPF** to protect your email domain from spoofing

---

## DHCP — Dynamic Host Configuration Protocol

### How DHCP Works (DORA Process)

```
Client                               DHCP Server
  │                                       │
  │── DISCOVER (broadcast) ─────────────► │
  │    "I need an IP address"            │
  │                                       │
  │ ◄── OFFER ───────────────────────── │
  │    "I offer you 192.168.1.50"        │
  │                                       │
  │── REQUEST (broadcast) ──────────────► │
  │    "I accept 192.168.1.50"           │
  │                                       │
  │ ◄── ACK ─────────────────────────── │
  │    "Confirmed. Lease = 24 hours"     │
```

DHCP assigns: IP address, subnet mask, default gateway, DNS servers, lease time.

### DHCP Security Threats

| Threat | Mechanism | Defensive Control |
|--------|-----------|------------------|
| Rogue DHCP Server | Attacker sets up unauthorized DHCP; can assign attacker-controlled gateway/DNS | **DHCP Snooping** on managed switches |
| DHCP Starvation | Attacker sends thousands of DHCP requests with spoofed MACs, exhausting the IP pool | **Rate limiting** DHCP requests per port; **Port Security** |
| DHCP Spoofing | Similar to rogue DHCP; intercepting requests | DHCP Snooping trust ports |

### DHCP Snooping (Cisco IOS)

```
ip dhcp snooping
ip dhcp snooping vlan 1-100

! Mark ONLY the port connected to the real DHCP server as trusted
interface GigabitEthernet0/1
 description Uplink to Distribution (DHCP Server here)
 ip dhcp snooping trust

! All other ports are untrusted by default
! Untrusted ports: DHCP OFFERs are dropped
```

---

## HTTP/S — HyperText Transfer Protocol (Secure)

### HTTP Request/Response Cycle

```
Client (Browser)                        Server
      │                                   │
      │── GET /login HTTP/1.1 ──────────► │
      │   Host: example.com              │
      │   Cookie: session=abc123         │
      │                                   │
      │ ◄── HTTP/1.1 200 OK ──────────── │
      │     Content-Type: text/html      │
      │     Set-Cookie: session=xyz789   │
      │     [HTML Body]                  │
```

### Critical HTTP Security Headers

| Header | Purpose | Recommended Value |
|--------|---------|------------------|
| `Strict-Transport-Security` | Forces HTTPS | `max-age=63072000; includeSubDomains; preload` |
| `Content-Security-Policy` | Prevents XSS by controlling resource sources | `default-src 'self'; script-src 'self'` |
| `X-Content-Type-Options` | Prevents MIME sniffing | `nosniff` |
| `X-Frame-Options` | Prevents clickjacking | `DENY` or `SAMEORIGIN` |
| `Referrer-Policy` | Controls referrer header disclosure | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Controls browser feature access | `geolocation=(), microphone=()` |

```nginx
# Nginx: Recommended security headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-RANDOM'; style-src 'self';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Checking Security Headers

```bash
# Use curl to inspect response headers
curl -I https://example.com

# Or use the online tool: https://securityheaders.com
# (Safe to check your own domains)
```

---

## TCP/IP — The Internet Protocol Suite

### IPv4 Packet Structure (Simplified)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |   DSCP/ECN    |         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Source Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Security-relevant fields:**
- **TTL (Time to Live):** Decremented at each hop; OS fingerprinting uses default TTL values (Windows: 128, Linux: 64)
- **Protocol:** 6 = TCP, 17 = UDP, 1 = ICMP
- **Flags (in TCP):** SYN, ACK, FIN, RST, PSH — used by firewalls for stateful inspection

### Common Port Reference

```
Well-Known Ports (0–1023) — require root/admin to bind:
  20/21  FTP (replace with SFTP on 22)
  22     SSH (change from default for security obscurity)
  23     Telnet (NEVER use in production)
  25     SMTP (email sending)
  53     DNS
  67/68  DHCP
  80     HTTP (redirect to 443)
  110    POP3 (use IMAPS/SMTPS instead)
  143    IMAP
  443    HTTPS
  445    SMB (patch rigorously; high-value target)
  3389   RDP (restrict to VPN; high-value target)

Registered Ports (1024–49151):
  1433   MS SQL Server
  3306   MySQL/MariaDB
  5432   PostgreSQL
  5900   VNC (use only over VPN with strong auth)
  8080   HTTP alt (dev servers)
  8443   HTTPS alt
```

---

## Practice Challenge

**Protocol Analysis Task:**

1. Use Wireshark in your lab to capture traffic to a site over HTTP (not HTTPS).
2. Apply filter: `http`
3. Find a GET request and examine the full packet tree. Identify the encapsulation at each layer:
   - Layer 2: Ethernet frame (source/destination MAC)
   - Layer 3: IP header (source/destination IP, TTL, Protocol=6)
   - Layer 4: TCP segment (source port, destination port, sequence number, flags)
   - Layer 7: HTTP request (method, URI, headers)
4. Now capture HTTPS traffic to the same site. What can you see at the Application layer now?
5. What does this tell you about the importance of TLS?
