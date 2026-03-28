# 06 — Blue Team Operations

> **Back to:** [Main Roadmap](../README.md)

---

## Overview

Blue Team Operations encompasses the defensive practices that security teams use to detect, respond to, and recover from cyber threats. Unlike penetration testing, blue team work is continuous — defenders must be right every time, while attackers only need to succeed once. This directory covers the core disciplines of modern defensive security operations.

---

## Learning Objectives

By completing this module you will be able to:

- Deploy and configure a Security Information and Event Management (SIEM) system to aggregate and correlate security events
- Write detection rules and correlation logic to identify suspicious activity
- Conduct proactive threat hunting using hypothesis-driven methodologies and MITRE ATT&CK
- Configure and tune Intrusion Detection/Prevention Systems (IDS/IPS)
- Integrate multiple security tools into a unified defensive monitoring pipeline
- Understand the critical log sources required for effective detection coverage

---

## Table of Contents

| # | File | Description |
|---|------|-------------|
| 1 | [SIEM and Log Management](./SIEM_and_Log_Management.md) | Building, tuning, and querying SIEM platforms; critical Windows Event IDs; ELK Stack and Wazuh; log forwarding |
| 2 | [Threat Hunting](./Threat_Hunting.md) | Hypothesis-driven hunting; MITRE ATT&CK; hunting lateral movement and persistence; Velociraptor and OSQuery |
| 3 | [IDS/IPS Configuration](./IDS_IPS_Configuration.md) | Snort vs. Suricata; writing and tuning rules; network TAPs vs. SPAN ports; Zeek for NSM |

---

## Recommended Study Order

```
SIEM_and_Log_Management.md  →  Threat_Hunting.md  →  IDS_IPS_Configuration.md
```

Start with SIEM fundamentals to understand how events are collected and correlated, then advance to proactive hunting techniques, and finally layer in network-level detection with IDS/IPS.

---

## Prerequisites

Before starting this module, ensure you have covered:

- [01_Foundations](../01_Foundations/) — Core security concepts and the CIA triad
- [02_Networking](../02_Networking/) — TCP/IP, protocols, and network traffic analysis
- [03_System_Security](../03_System_Security/) — Windows and Linux hardening fundamentals

---

## Key Tools Covered

| Tool | Category | Free/Open Source |
|------|----------|-----------------|
| Elastic SIEM / ELK Stack | SIEM | ✅ Open Source |
| Wazuh | HIDS / SIEM | ✅ Open Source |
| Splunk (Free Tier) | SIEM | ⚠️ Free up to 500 MB/day |
| Winlogbeat / Filebeat | Log Forwarding | ✅ Open Source |
| Suricata | IDS/IPS | ✅ Open Source |
| Snort | IDS/IPS | ✅ Open Source |
| Zeek (Bro) | NSM | ✅ Open Source |
| Velociraptor | Threat Hunting / DFIR | ✅ Open Source |
| OSQuery | Endpoint Visibility | ✅ Open Source |
| Sigma | Detection Rules | ✅ Open Source |

---

## Lab Environment Recommendations

A minimal home lab for this module requires:

- **SIEM host:** 8 GB RAM, 4 vCPUs, 200 GB disk (for ELK or Wazuh)
- **Windows endpoint:** Windows 10/11 VM for generating and forwarding logs
- **Linux endpoint:** Ubuntu or Debian VM with auditd configured
- **Network segment:** Isolated virtual network (NAT or host-only) in VirtualBox/VMware

---

*This module is part of the [CyberPath Complete Cybersecurity Roadmap](../README.md).*
