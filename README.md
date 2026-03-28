# 🛡️ Ultimate Cybersecurity Roadmap & Defense Toolkit

> **CyberPath** — A comprehensive, production-ready hub for defensive security education and practical implementation. Built for learners at every level, from absolute beginner to enterprise security architect.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Defensive Only](https://img.shields.io/badge/Policy-Defensive%20Only-green.svg)](#contributing)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## 🎯 Value Proposition

This repository provides a structured, actionable path from foundational IT knowledge to advanced defensive security architecture. Every guide, script, and concept is focused exclusively on **authorization**, **awareness**, **prevention**, and **defensive analysis** — never offensive exploitation.

**Who is this for?**
- Students preparing for Security+, CySA+, or OSCP certifications
- IT professionals transitioning into cybersecurity roles (SOC Analyst, IR Engineer, Cloud Security Engineer)
- Security practitioners who want a quick-reference defensive encyclopedia
- Organizations building internal security training programs

---

## 📚 Table of Contents

| # | Directory | Focus Area |
|---|-----------|------------|
| 01 | [Foundations](01_Foundations/) | CIA Triad, Ethics, Legal Standards, Computing Basics |
| 02 | [Networking](02_Networking/) | OSI/TCP-IP Models, Protocols, Subnetting |
| 03 | [System Security](03_System_Security/) | OS Hardening (Windows/Linux), Permissions, Services |
| 04 | [Web Security](04_Web_Security/) | OWASP Top 10 Mitigation, Secure API Design, WAF |
| 05 | [Cloud Security](05_Cloud_Security/) | IAM, Shared Responsibility, AWS/Azure/GCP Hardening |
| 06 | [Blue Team Ops](06_Blue_Team_Ops/) | SIEM, IDS/IPS, Threat Hunting, Log Management |
| 07 | [Malware Defense](07_Malware_Defense/) | Static/Dynamic Analysis, YARA, Sandbox Configuration |
| 08 | [Incident Response](08_Incident_Response/) | PICERL Lifecycle, Forensics, Playbooks |
| 09 | [Defensive Tooling](09_Defensive_Tooling/) | PowerShell, Python & Bash Scripts for Monitoring |
| 10 | [A-Z Roadmap](10_A-Z_Roadmap/) | Alphabetical Encyclopedic Reference (26 Concepts) |
| 11 | [Checklists & Audits](11_Checklists_Audits/) | Hardening Checklists, Self-Audit Templates |

---

## 🗺️ Learning Path Overview

```
Stage 1: Beginner    (Months 0–3)   → Foundations, Networking, Lab Setup → Target: CompTIA Security+
Stage 2: Intermediate (Months 4–9)  → Web Security, SOC Workflows        → Target: CySA+ / BTL1
Stage 3: Advanced    (Months 10–18) → IR, Cloud, Threat Intel             → Target: OSCP / CASP+
Stage 4: Expert      (24+ Months)   → Zero Trust Architecture, Leadership → Target: CISSP / CISM
```

---

## 🖥️ Lab Environment Setup

All practical exercises in this repository are designed to be performed in a **safe, isolated lab environment**. Never test against systems you do not own or have explicit written permission to test.

### Recommended Virtual Lab Stack

```bash
# Option 1: VirtualBox (Free)
# Download: https://www.virtualbox.org/
# Recommended VMs: Kali Linux (tools), Ubuntu Server (target), Windows Server 2022 (target)

# Option 2: VMware Workstation Player (Free for personal use)
# Download: https://www.vmware.com/products/workstation-player.html

# Option 3: Cloud-Based Labs (No local hardware required)
# - TryHackMe:  https://tryhackme.com     (Guided, beginner-friendly)
# - HackTheBox: https://hackthebox.com    (Challenge-based, intermediate)
# - RangeForce: https://rangeforce.com    (Enterprise SOC training)
```

### Network Isolation Checklist

- [ ] Set all lab VMs to **Host-Only** or **Internal Network** adapter mode
- [ ] Never connect lab VMs containing vulnerable software to the internet
- [ ] Use snapshots liberally — revert to a clean state after each exercise
- [ ] Keep your host OS patched and separate from lab traffic

---

## 🏅 Certification Roadmap

| Certification | Level | Cost (USD) | Focus | Recommended Stage |
|---------------|-------|-----------|-------|-------------------|
| CompTIA Security+ | Foundational | ~$392 | Broad security fundamentals | Stage 1 |
| CompTIA CySA+ | Intermediate | ~$392 | Blue team / SOC operations | Stage 2 |
| BTL1 (Blue Team Labs) | Intermediate | ~$399 | Hands-on defensive analysis | Stage 2 |
| CEH | Intermediate | ~$950 | Ethical hacking methodology | Stage 3 |
| OSCP | Advanced | ~$1,499 | Practical penetration testing | Stage 3 |
| CASP+ | Advanced | ~$494 | Enterprise security architecture | Stage 3–4 |
| CISM | Expert | ~$575 | Security management | Stage 4 |
| CISSP | Expert | ~$749 | Security leadership & governance | Stage 4 |

---

## 🔑 Top 100 Cybersecurity Concepts

| Category | Key Concepts |
|----------|-------------|
| **Fundamentals** | CIA Triad, Defense-in-Depth, Principle of Least Privilege, Non-repudiation, Zero Trust, Risk Assessment |
| **Networking** | OSI Model, TCP/IP, DNSSEC, VPN, VLAN, ARP Spoofing, MITM, IDS/IPS, WAF, SDN |
| **Access Control** | IAM, RBAC, ABAC, MFA, SSO, OAuth, Biometrics, Active Directory, Kerberos, NTLM |
| **Threats/Malware** | APT, Ransomware, Trojan, Rootkit, Botnet, Phishing, Social Engineering, Zero-Day |
| **Systems/Cloud** | Hardening, GPO, Registry, Kernel Security, IaaS, PaaS, SaaS, Shared Responsibility |
| **Blue Team Ops** | SIEM, SOC, UEBA, EDR/XDR, Vulnerability Management, Patching, Log Analysis |
| **IR/Forensics** | PICERL, Forensics, Chain of Custody, Memory Forensics, BC/DR, BIA, MTD |
| **Web Security** | SQLi, XSS, CSRF, Secure Headers, Input Validation, Clickjacking, Session Hijacking |
| **Cryptography** | AES, RSA, SHA-256, PKI, Digital Certificates, Hashing, Salting, SSL/TLS, PFS |
| **Compliance/Ethics** | GDPR, HIPAA, PCI DSS, SOX, Ethics, Liability, Governance, White/Grey/Black Hat |

---

## 📋 Daily Learning Tracker Template

Copy this template into your personal `Writeup/` folder and fill it in daily:

```markdown
## Study Log — [Date]

**Session Duration:** ___ hours
**Topics Covered:**
- [ ] Topic 1
- [ ] Topic 2

**Labs Completed:**
- Lab name / platform

**Key Takeaways:**
> Write 2–3 sentences summarizing what you learned.

**Questions / Follow-up:**
- Something I want to research further
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide. The core rule: **all contributions must be defensive in nature**. No offensive exploitation techniques, no dual-use tools without explicit defensive context.

---

## ⚖️ Legal Disclaimer

All content in this repository is provided for **educational and defensive purposes only**. Any techniques or tools described must only be used on systems and networks you **own or have explicit written permission** to test. Unauthorized access to computer systems is illegal and unethical. The maintainers of this repository accept no liability for misuse.

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

