# Z — Zero Trust

## Beginner Explanation
Zero Trust is a security philosophy built on "never trust, always verify." Every user, device, and application must prove identity and meet security requirements before accessing any resource — regardless of network location. One breach inside the network no longer means unrestricted access everywhere.

## Technical Deep Dive

### Traditional Perimeter vs. Zero Trust
```
Traditional (Castle-and-Moat):
  Inside network  → Automatically trusted → Access granted to everything
  Problem: Attacker who breaches the perimeter moves freely across all systems

Zero Trust:
  Every request   → Verify identity + device health + context → Least-privilege access
  Breach contained: attacker with one credential cannot freely pivot to other systems
```

### Zero Trust Pillars (NIST SP 800-207)
| Pillar | What It Means | Example Controls |
|--------|--------------|-----------------|
| **Identity** | Verify who is requesting | MFA, passwordless auth, risk-based Conditional Access |
| **Device** | Verify device health | MDM compliance, EDR enrolled, OS patched |
| **Network** | Segment and encrypt all traffic | Micro-segmentation, ZTNA, TLS everywhere |
| **Application** | Per-app authorization | App-level policies, CASB |
| **Data** | Classify and protect data | DLP, encryption, sensitivity labels |

### ZTNA vs. VPN
```
VPN:  Authenticate once → full internal network access
      Stolen credentials = attacker can reach any internal system

ZTNA: Authenticate → device health checked → access ONLY the specific app requested
      Stolen credentials cannot reach other systems; no implicit network access
```

### Implementation Roadmap
```
Phase 1 — Strong Identity (Start Here — Highest ROI):
  ✓ MFA on every account (blocks 99% of credential-based attacks)
  ✓ Passwordless for privileged accounts
  ✓ Conditional Access: block legacy auth, require compliant device

Phase 2 — Device Trust:
  ✓ MDM enrollment required before accessing corporate resources
  ✓ Device compliance policy: encrypted disk, patched OS, EDR enrolled
  ✓ Certificate-based device identity

Phase 3 — Least-Privilege Network Access:
  ✓ ZTNA replaces always-on VPN for remote access
  ✓ Micro-segmentation for servers and critical workloads
  ✓ JIT privileged access for sensitive systems

Phase 4 — Data Protection:
  ✓ Data classification and sensitivity labels applied
  ✓ DLP enforcement based on data classification
  ✓ Encryption at rest and in transit for all data tiers
```

### Conditional Access Policy Example (Azure AD / Entra ID)
```
Policy: "Require MFA and Compliant Device for Microsoft 365"
Assignments:
  Users:      All users
  Cloud Apps: Microsoft 365
Conditions:
  Any device platform, any location
Grant:
  Require multi-factor authentication
  Require device to be marked as compliant
  (Require ALL selected controls)
```

### ZTNA Providers
| Product | Vendor |
|---------|--------|
| Zscaler Private Access | Zscaler |
| Cloudflare Access | Cloudflare |
| Microsoft Entra Private Access | Microsoft |
| Palo Alto Prisma Access | Palo Alto Networks |

## Real-World Relevance
**Colonial Pipeline (2021):** Attackers gained access via a legacy VPN account — no MFA, broad network access granted. A Zero Trust architecture requiring MFA, device compliance, and ZTNA (application-specific access) would have prevented the $4.4M ransom payment and 5-day fuel shortage that affected the US East Coast.

## Defensive Measures
1. Enable MFA on every account immediately — this single control prevents the majority of account takeovers
2. Deploy Conditional Access to enforce device compliance before granting resource access
3. Replace always-on VPN with ZTNA for application-specific, least-privilege remote access
4. Implement micro-segmentation to contain lateral movement even after a breach
5. Use the CISA Zero Trust Maturity Model to track progress and plan your roadmap

## Practice Challenge
1. Implement a Conditional Access policy in Azure AD (free trial) requiring MFA for all sign-ins.
2. Test it: sign in from a non-compliant device and verify access is blocked.
3. Score your current environment against all five Zero Trust pillars (1–5 each) and identify the highest-impact gap.
4. Write a one-page Zero Trust roadmap for your organization's next 12 months.
