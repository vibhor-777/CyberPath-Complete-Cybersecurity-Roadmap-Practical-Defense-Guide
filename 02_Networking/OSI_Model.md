# The OSI Model — Threats and Defenses at Every Layer

## Beginner Explanation

The **OSI (Open Systems Interconnection) Model** is a conceptual framework that standardizes how different network systems communicate. Think of it as a 7-floor building where each floor has a specific job, and data travels from the top floor down to be sent — and from the bottom floor up when received.

Attackers can target any floor. Defenders need to know what each floor does and how to protect it.

---

## The Seven Layers at a Glance

```
┌─────────────────────────────────────────────────────────┐
│  Layer 7 - Application   │  HTTP, HTTPS, DNS, FTP, SMTP │
├─────────────────────────────────────────────────────────┤
│  Layer 6 - Presentation  │  SSL/TLS, JPEG, ASCII, Crypto│
├─────────────────────────────────────────────────────────┤
│  Layer 5 - Session       │  NetBIOS, RPC, NFS           │
├─────────────────────────────────────────────────────────┤
│  Layer 4 - Transport     │  TCP, UDP                    │
├─────────────────────────────────────────────────────────┤
│  Layer 3 - Network       │  IP, ICMP, IPsec, OSPF       │
├─────────────────────────────────────────────────────────┤
│  Layer 2 - Data Link     │  Ethernet, ARP, 802.11 (Wi-Fi)│
├─────────────────────────────────────────────────────────┤
│  Layer 1 - Physical      │  Cables, Switches, Fiber     │
└─────────────────────────────────────────────────────────┘
```

Data is **encapsulated** as it travels down from Layer 7 to Layer 1 (adding headers at each layer) and **de-encapsulated** as it travels up from Layer 1 to Layer 7 (stripping headers).

---

## Layer-by-Layer Threat and Defense Analysis

### Layer 7 — Application Layer

**Purpose:** Provides network services directly to user applications.

**Key Protocols:** HTTP, HTTPS, FTP, DNS, SMTP, SNMP

| Threat | Description | Defensive Control |
|--------|-------------|------------------|
| SQL Injection | Malicious SQL embedded in web inputs | Parameterized queries, WAF |
| Cross-Site Scripting (XSS) | Malicious scripts injected into web pages | Output encoding, CSP headers |
| DNS Hijacking | Attacker alters DNS responses to redirect traffic | DNSSEC, DNS-over-HTTPS, trusted resolvers |
| FTP Clear-text | Credentials transmitted unencrypted | Replace FTP with SFTP or FTPS |
| SMTP Spoofing | Forged sender addresses in emails | SPF, DKIM, DMARC records |
| Command Injection | OS commands injected through application inputs | Input validation, sandboxed execution |

**Defensive Priority:** Deploy a **Web Application Firewall (WAF)**, implement DNSSEC, enforce HTTPS-only, and validate/sanitize all user inputs.

---

### Layer 6 — Presentation Layer

**Purpose:** Data formatting, encryption, and compression.

**Key Protocols/Formats:** SSL/TLS, JPEG, ASCII, MPEG

| Threat | Description | Defensive Control |
|--------|-------------|------------------|
| SSL Stripping | Downgrade HTTPS to HTTP | HTTP Strict Transport Security (HSTS) |
| Weak Cipher Suites | Use of outdated algorithms (RC4, DES) | Enforce TLS 1.2+ with strong cipher suites |
| Certificate Spoofing | Presenting fraudulent TLS certificates | Certificate Transparency (CT) logs, CAA DNS records |
| POODLE / BEAST | Protocol downgrade exploits | Disable SSL 3.0, TLS 1.0, TLS 1.1 |

**TLS Configuration Best Practice:**
```nginx
# Nginx: Enforce modern TLS only
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security "max-age=63072000" always;
```

---

### Layer 5 — Session Layer

**Purpose:** Manages sessions (establishment, maintenance, termination) between applications.

**Key Protocols:** NetBIOS, RPC, NFS, SQL sessions

| Threat | Description | Defensive Control |
|--------|-------------|------------------|
| Session Hijacking | Stealing a valid session token | Secure + HttpOnly cookies, short session timeouts, token rotation |
| Session Fixation | Forcing a user to use a known session ID | Regenerate session ID after authentication |
| RPC Exploitation | Abusing Remote Procedure Call services | Disable unused RPC endpoints, firewall rules |

---

### Layer 4 — Transport Layer

**Purpose:** End-to-end communication, error checking, flow control.

**Key Protocols:** TCP (reliable), UDP (fast/unreliable)

| Threat | Description | Defensive Control |
|--------|-------------|------------------|
| SYN Flood (DDoS) | Exhausts server connection queue with half-open TCP connections | SYN cookies, rate limiting, DDoS scrubbing |
| Port Scanning | Enumerating open ports to identify attack surface | Firewall to allow only required ports, port knocking |
| UDP Amplification | Sending small requests to services that reply with large responses (DNS, NTP) | Rate limiting UDP reflection, BCP38 filtering |
| TCP Session Hijacking | Predicting TCP sequence numbers to inject data | Randomized Initial Sequence Numbers (ISN), encrypted sessions |

**The TCP Three-Way Handshake:**
```
Client                          Server
  │                               │
  │──── SYN (ISN=1000) ─────────► │
  │                               │
  │ ◄─── SYN-ACK (ISN=5000, ─────│
  │       ACK=1001) ──────────── │
  │                               │
  │──── ACK (ACK=5001) ─────────► │
  │                               │
  [Connection Established]
```

**SYN Cookie Defense:**
```bash
# Linux: Enable SYN cookies (protects against SYN flood)
sysctl -w net.ipv4.tcp_syncookies=1
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
```

---

### Layer 3 — Network Layer

**Purpose:** Logical addressing and routing.

**Key Protocols:** IPv4, IPv6, ICMP, OSPF, BGP, IPsec

| Threat | Description | Defensive Control |
|--------|-------------|------------------|
| IP Spoofing | Forging source IP addresses | Ingress/egress filtering (BCP38), IPsec |
| ICMP Tunneling | Hiding data in ICMP packets to bypass firewalls | Deep packet inspection, block outbound ICMP echo from non-admins |
| BGP Hijacking | Advertising fraudulent routing prefixes to intercept traffic | RPKI (Resource Public Key Infrastructure), BGP monitoring |
| Routing Table Poisoning | Injecting false routes | Route authentication (MD5 or HMAC on OSPF/BGP) |

**IPsec Tunnel — Defensive Use:**
```bash
# IPsec provides Layer 3 encryption (used for VPNs and site-to-site tunnels)
# strongSwan example (Linux)
# /etc/ipsec.conf
conn site-to-site
    type=tunnel
    left=%defaultroute
    leftsubnet=192.168.1.0/24
    right=203.0.113.10
    rightsubnet=10.0.0.0/24
    authby=pubkey
    keyexchange=ikev2
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
    auto=start
```

---

### Layer 2 — Data Link Layer

**Purpose:** Node-to-node data transfer; hardware addressing (MAC).

**Key Protocols:** Ethernet, ARP (Address Resolution Protocol), 802.11 (Wi-Fi), VLAN (802.1Q)

| Threat | Description | Defensive Control |
|--------|-------------|------------------|
| ARP Poisoning | Sending fake ARP replies to associate attacker's MAC with legitimate IP (enables MITM) | Dynamic ARP Inspection (DAI) on managed switches |
| MAC Spoofing | Changing NIC's MAC address to bypass MAC filtering | 802.1X port authentication (not just MAC filtering alone) |
| VLAN Hopping | Exploiting 802.1Q to access VLANs beyond the attacker's authorization | Disable DTP, set native VLAN to unused VLAN ID |
| Rogue DHCP Server | Attacker runs a DHCP server to assign their own gateway/DNS | DHCP Snooping on managed switches |

**Switch Hardening Commands (Cisco IOS):**
```
! Enable DHCP Snooping
ip dhcp snooping
ip dhcp snooping vlan 10,20
no ip dhcp snooping information option
interface GigabitEthernet0/1
 ip dhcp snooping trust   ! Only on uplinks to legitimate DHCP server

! Enable Dynamic ARP Inspection
ip arp inspection vlan 10,20
interface GigabitEthernet0/1
 ip arp inspection trust   ! Only on uplinks

! Enable Port Security
interface GigabitEthernet0/2
 switchport mode access
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
```

---

### Layer 1 — Physical Layer

**Purpose:** Raw bit transmission; hardware.

| Threat | Description | Defensive Control |
|--------|-------------|------------------|
| Physical Eavesdropping | Tapping network cables | Fiber optic (harder to tap without disruption), physical security |
| Rogue Device Insertion | Plugging unauthorized devices into network ports | 802.1X NAC, physical port lockdown, cable locks |
| Hardware Keyloggers | Physical keyloggers attached between keyboard and PC | Physical inspection, sealed cable ports |
| Power Attacks | UPS failures causing availability loss | Redundant power, UPS, generator |

---

## Real-World Relevance

**ARP Poisoning — "The Lazy Hacker's MITM":** In countless enterprise breaches, once an attacker has a foothold on an internal network, ARP poisoning is a trivially simple way to intercept traffic between workstations and the default gateway. The 2015 Carbanak banking group used MITM positioning to observe banking operations before executing fraud. Dynamic ARP Inspection would have detected and blocked their poisoning attempts.

---

## Defensive Measures Summary

| Layer | Top Defensive Control |
|-------|-----------------------|
| 7 — Application | WAF, input validation, DNSSEC |
| 6 — Presentation | TLS 1.3, disable legacy ciphers, HSTS |
| 5 — Session | Secure session management, token rotation |
| 4 — Transport | Stateful firewall, SYN cookies, rate limiting |
| 3 — Network | BCP38 filtering, IPsec, RPKI |
| 2 — Data Link | DHCP Snooping, DAI, 802.1X, port security |
| 1 — Physical | Physical security, 802.1X NAC, cable management |

---

## Practice Challenge

**Network Analysis Task:**

1. In a lab environment (Wireshark on your host, capturing a VM's traffic), capture the traffic for a web request to a HTTP site.
2. Apply the filter `tcp.flags.syn == 1` to find the TCP SYN packet.
3. Note the **Initial Sequence Number (ISN)** in the packet details.
4. Follow the stream (Right-click → Follow → TCP Stream) to see the complete three-way handshake.
5. Answer: Why does randomizing the ISN protect against session hijacking?

Document your findings and screenshots in your `Writeup/` folder.
