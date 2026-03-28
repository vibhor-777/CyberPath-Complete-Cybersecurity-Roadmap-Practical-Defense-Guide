# The CIA Triad — The Foundation of Information Security

## Beginner Explanation

Think of securing a bank vault:

- **Confidentiality** = Only the bank manager and authorized tellers can open it. Unauthorized people cannot see what's inside.
- **Integrity** = The money inside hasn't been tampered with. You're sure the amount is exactly what was deposited.
- **Availability** = When an authorized teller needs to access the vault during business hours, it opens. It's not locked away when legitimately needed.

Every security control ever built maps back to protecting at least one of these three properties.

---

## Technical Deep Dive

### Confidentiality

**Goal:** Prevent unauthorized disclosure of information.

**Primary Controls:**
| Control | Mechanism | Example |
|---------|-----------|---------|
| Encryption at rest | AES-256 | BitLocker full disk encryption |
| Encryption in transit | TLS 1.3 | HTTPS web traffic |
| Access control | RBAC / ACLs | NTFS file permissions |
| Data masking | Tokenization | Masking credit card numbers in logs |

**Threats to Confidentiality:**
- Eavesdropping / packet sniffing (mitigate with TLS)
- Insider threats (mitigate with least privilege + DLP)
- Shoulder surfing (mitigate with privacy screens + policies)
- Data exfiltration via malware (mitigate with EDR + network monitoring)

### Integrity

**Goal:** Ensure data has not been altered in an unauthorized manner.

**Primary Controls:**
| Control | Mechanism | Example |
|---------|-----------|---------|
| Hashing | SHA-256, SHA-3 | Verifying downloaded file checksums |
| Digital signatures | RSA / ECDSA | Code signing certificates |
| Message Authentication Codes | HMAC-SHA256 | API request signing |
| File Integrity Monitoring | Hash comparison | Tripwire, AIDE, custom FIM scripts |

**Threats to Integrity:**
- Man-in-the-Middle attacks (mitigate with TLS + HSTS)
- SQL injection that modifies database records (mitigate with parameterized queries)
- Malicious firmware updates (mitigate with signed firmware + Secure Boot)
- Log tampering (mitigate with write-once log storage + SIEM)

**Hashing Example:**
```bash
# Verify integrity of a downloaded file
sha256sum ubuntu-22.04.iso
# Compare output to the hash published on the official download page
```

### Availability

**Goal:** Ensure systems and data are accessible when legitimately needed.

**Primary Controls:**
| Control | Mechanism | Example |
|---------|-----------|---------|
| Redundancy | RAID, clustering | Database server clusters |
| Disaster Recovery Planning (DRP) | Backup + failover | Off-site backups, hot standby |
| DDoS mitigation | Traffic scrubbing | Cloudflare, AWS Shield |
| Patch management | Vulnerability remediation | Preventing exploits that crash services |

**Threats to Availability:**
- DDoS attacks (mitigate with rate limiting, CDN, scrubbing)
- Ransomware (mitigate with offline backups + network segmentation)
- Hardware failure (mitigate with RAID + UPS + failover)
- Misconfiguration (mitigate with change management + IaC)

---

## The Relationship Between CIA Properties

These three pillars often create **tension**:

```
HIGH CONFIDENTIALITY ←→ may reduce AVAILABILITY
(Encrypting everything can add latency and complexity)

HIGH AVAILABILITY ←→ may reduce CONFIDENTIALITY
(Replicating data everywhere increases the attack surface)

STRONG INTEGRITY CONTROLS ←→ may slow AVAILABILITY
(Hash verification adds processing time)
```

The security professional's job is to find the **right balance** based on the **business impact analysis (BIA)** for each data asset.

---

## Extended Triad: Non-Repudiation and Authenticity

Many frameworks extend the CIA Triad with two additional properties:

- **Non-repudiation:** A user cannot deny having performed an action. Implemented via audit logs, digital signatures, and timestamps. Critical for legal proceedings.
- **Authenticity:** Verifying that data or a user is genuine. Implemented via MFA, certificates, and message authentication codes.

---

## Real-World Relevance

**Confidentiality breach:** The 2017 Equifax breach exposed Social Security Numbers, birth dates, and addresses of 147 million people because unpatched Apache Struts software allowed attackers to exfiltrate data.

**Integrity breach:** In 2020, SolarWinds supply chain attackers modified legitimate software updates with a backdoor (SUNBURST), compromising the integrity of software trusted by 18,000 organizations.

**Availability breach:** In 2021, a ransomware attack on Colonial Pipeline shut down 5,500 miles of fuel pipeline for six days, disrupting fuel supply across the US East Coast.

---

## Defensive Measures

1. **Conduct a Data Classification exercise** — Categorize all data assets by confidentiality level (Public, Internal, Confidential, Restricted).
2. **Map each asset to its CIA requirements** — A patient medical record requires all three; a public marketing brochure primarily requires integrity and availability.
3. **Select controls proportional to risk** — The cost of a control should never exceed the value of the asset it protects.
4. **Test your controls** — Run tabletop exercises for availability (simulate a server outage), integrity tests (verify backup hash chains), and confidentiality audits (check who has access to sensitive data).

---

## Practice Challenge

**Task:** Perform a personal CIA audit.

1. List 5 data assets you interact with regularly (e.g., email, banking app, work files, personal photos).
2. For each, rate its Confidentiality, Integrity, and Availability requirements on a scale of 1–5.
3. Identify one control currently protecting each pillar.
4. Identify one gap where a control is missing or weak.
5. Write a one-paragraph remediation plan for the most critical gap.

Document your findings in your `Writeup/` folder.
