# X — XDR (Extended Detection and Response)

## Beginner Explanation
XDR integrates telemetry from endpoints, network, email, cloud, and identity into a unified detection platform. It correlates signals across your entire environment to show the full attack chain rather than isolated, disconnected alerts.

## Technical Deep Dive

### EDR vs XDR vs SIEM
| Capability | EDR | XDR | SIEM |
|------------|-----|-----|------|
| Endpoint telemetry | Yes | Yes | Varies |
| Network / Email / Cloud | No | Yes | Varies |
| Built-in response actions | Yes | Yes | No |
| Log management | No | Limited | Yes |
| Advanced correlation | Basic | Advanced | Advanced |

### XDR Attack Chain Correlation Example
```
Email Security  → Phishing link clicked (not blocked — user interaction required)
Endpoint (EDR)  → PowerShell download cradle → payload.exe dropped
Identity        → Credential dump detected → anomalous new logon from harvested creds
Network         → Lateral movement via SMB to file server
Endpoint        → Shadow copy deletion → mass file encryption begins
─────────────────────────────────────────────────────────────────────
XDR Incident    → Single correlated story: Phishing → Initial Access →
                  Credential Theft → Lateral Movement → Ransomware
Auto-response   → Isolate patient-zero, block C2 IP, alert SOC
```

### One-Click Response Actions
- **Endpoint:** Isolate host, terminate process, quarantine file, collect artifact
- **Identity:** Disable account, revoke all sessions, force MFA re-enrollment
- **Network:** Block IP/domain at firewall, block URL at proxy
- **Email:** Purge malicious messages from all mailboxes simultaneously

### Leading XDR Platforms
| Product | Vendor |
|---------|--------|
| Microsoft Defender XDR | Microsoft |
| CrowdStrike Falcon XDR | CrowdStrike |
| Palo Alto Cortex XDR | Palo Alto Networks |
| SentinelOne Singularity | SentinelOne |
| Trend Micro Vision One | Trend Micro |

## Real-World Relevance
**SolarWinds (2020):** Detection required correlating anomalous SAML token usage (identity), lateral movement to cloud resources (cloud), and unusual API calls (network). No single EDR or SIEM alert told the full story. Organizations with XDR correlating all three detected SUNBURST weeks earlier than endpoint-only deployments.

## Defensive Measures
1. Consolidate EDR, email security, and network detection into an XDR platform
2. Ingest identity telemetry (Azure AD, Okta sign-in logs) — identity is the new perimeter
3. Enable automated response playbooks for high-confidence alerts
4. Tune detection rules to reduce alert fatigue — XDR value is lost if SOC ignores alerts
5. Measure MTTD and MTTR; XDR should demonstrably improve both

## Practice Challenge
1. Map a phishing → malware → C2 → data exfiltration scenario to the XDR data sources that would detect each step.
2. Write a SOAR playbook outline for automatically responding to a high-confidence ransomware alert.
3. If you have access to Microsoft Defender XDR (free trial available): enable all pillars and review the Incidents dashboard.
