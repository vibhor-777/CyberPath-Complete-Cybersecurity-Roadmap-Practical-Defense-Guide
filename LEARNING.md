# 📚 CyberPath Learning Roadmap

> **Your structured journey from cybersecurity beginner to advanced practitioner.**

This guide maps out a complete learning progression through the CyberPath repository. Follow the tracks sequentially or jump to your current skill level.

---

## 🗺️ Table of Contents

- [How to Use This Guide](#how-to-use-this-guide)
- [Beginner Track (Months 0–3)](#beginner-track-months-03)
- [Intermediate Track (Months 4–9)](#intermediate-track-months-49)
- [Advanced Track (Months 10–18)](#advanced-track-months-1018)
- [Expert Track (18+ Months)](#expert-track-18-months)
- [A–Z Reference Index](#az-reference-index)
- [Hands-On Labs & Exercises](#hands-on-labs--exercises)
- [Certification Alignment](#certification-alignment)
- [Recommended External Resources](#recommended-external-resources)

---

## How to Use This Guide

1. **Self-assess your level** using the prerequisite lists at the start of each track.
2. **Work through modules in order** — each builds on the previous.
3. **Complete the labs** in each section before moving on.
4. **Track your progress** using the daily log template in the README.
5. **Return to earlier modules** as needed — security is deeply interconnected.

---

## Beginner Track (Months 0–3)

**Prerequisites:** Basic computer literacy; curiosity about how systems work.  
**Goal:** Build foundational knowledge and earn CompTIA Security+.

### Module 1 — Foundations (`01_Foundations/`)

| File | Topic | Time |
|------|-------|------|
| [CIA_Triad.md](01_Foundations/CIA_Triad.md) | Confidentiality, Integrity, Availability | 2 hrs |
| [Computing_Basics.md](01_Foundations/Computing_Basics.md) | OS concepts, File systems, Processes | 4 hrs |
| [Ethics_and_Legal.md](01_Foundations/Ethics_and_Legal.md) | Legal frameworks, Responsible disclosure | 2 hrs |

**Key Concepts:** CIA Triad · Defense-in-depth · Principle of Least Privilege · Risk vs. Threat vs. Vulnerability

**Lab Exercise:**
- Set up a VirtualBox or VMware lab with Ubuntu Server and Windows 10
- Document your lab topology (IP ranges, network adapters)
- Complete the Network Isolation Checklist from the README

---

### Module 2 — Networking (`02_Networking/`)

| File | Topic | Time |
|------|-------|------|
| [OSI_Model.md](02_Networking/OSI_Model.md) | OSI & TCP/IP layers | 3 hrs |
| [Protocols_Deep_Dive.md](02_Networking/Protocols_Deep_Dive.md) | HTTP/S, DNS, DHCP, SSH, SMB | 4 hrs |
| [Network_Defense.md](02_Networking/Network_Defense.md) | Firewalls, VPNs, Network Segmentation | 3 hrs |

**Key Concepts:** OSI 7 layers · Packet structure · Port numbers · Firewall rules · VLANs · Subnetting

**Lab Exercise:**
- Capture traffic with Wireshark and identify at least 5 protocol types
- Configure a basic host-based firewall rule on your lab VM
- Perform a `nmap` scan (lab environment only) and interpret the output

---

### Module 3 — System Security Basics (`03_System_Security/`)

| File | Topic | Time |
|------|-------|------|
| [Linux_Hardening.md](03_System_Security/Linux_Hardening.md) | Users, SSH, firewall, services | 4 hrs |
| [Windows_Hardening.md](03_System_Security/Windows_Hardening.md) | GPO, Defender, RDP security | 4 hrs |
| [Service_Auditing.md](03_System_Security/Service_Auditing.md) | Identifying unnecessary services | 2 hrs |

**Lab Exercise:**
- Apply the Linux Hardening checklist to your Ubuntu lab VM
- Enable Windows Defender and configure Windows Firewall rules
- Use `systemctl list-units --type=service` and disable 3 unnecessary services

---

### Beginner Milestone Check
Before moving to Intermediate, you should be able to:
- [ ] Explain the CIA Triad with real-world examples
- [ ] Identify OSI layers and map common protocols to them
- [ ] Harden a basic Linux or Windows system from scratch
- [ ] Read and write basic firewall rules
- [ ] Describe what a VLAN is and why network segmentation matters

---

## Intermediate Track (Months 4–9)

**Prerequisites:** Completion of Beginner Track (or equivalent knowledge).  
**Goal:** Develop Blue Team and SOC skills; target CySA+ / BTL1.

### Module 4 — Web Security (`04_Web_Security/`)

| File | Topic | Time |
|------|-------|------|
| [OWASP_Top10.md](04_Web_Security/OWASP_Top10.md) | Top 10 web vulnerabilities (defensive) | 5 hrs |
| [Secure_API_Design.md](04_Web_Security/Secure_API_Design.md) | Authentication, rate limiting, input validation | 3 hrs |
| [WAF_Implementation.md](04_Web_Security/WAF_Implementation.md) | Web Application Firewall setup | 3 hrs |

**Key Concepts:** SQLi · XSS · CSRF · Secure headers · Input validation · API key management

**Lab Exercise:**
- Set up DVWA (Damn Vulnerable Web Application) in your lab
- Identify and document each OWASP Top 10 category in DVWA
- Configure ModSecurity WAF rules to block SQL injection attempts

---

### Module 5 — Cloud Security (`05_Cloud_Security/`)

| File | Topic | Time |
|------|-------|------|
| [Shared_Responsibility_Model.md](05_Cloud_Security/Shared_Responsibility_Model.md) | Cloud provider vs. customer responsibilities | 2 hrs |
| [IAM_Hardening.md](05_Cloud_Security/IAM_Hardening.md) | Roles, policies, least privilege in AWS/Azure/GCP | 4 hrs |
| [Cloud_Hardening_Checklists.md](05_Cloud_Security/Cloud_Hardening_Checklists.md) | Practical hardening across major cloud platforms | 3 hrs |

**Lab Exercise:**
- Create a free AWS or Azure account and explore IAM
- Implement MFA on your cloud account root/admin
- Review S3 or Blob Storage permissions and identify any public access

---

### Module 6 — Blue Team Operations (`06_Blue_Team_Ops/`)

| File | Topic | Time |
|------|-------|------|
| [SIEM_and_Log_Management.md](06_Blue_Team_Ops/SIEM_and_Log_Management.md) | Log ingestion, parsing, alerting | 5 hrs |
| [IDS_IPS_Configuration.md](06_Blue_Team_Ops/IDS_IPS_Configuration.md) | Snort/Suricata rules, tuning | 4 hrs |
| [Threat_Hunting.md](06_Blue_Team_Ops/Threat_Hunting.md) | Hypothesis-driven hunting, IOC analysis | 4 hrs |

**Key Concepts:** SIEM correlation rules · Log retention · Alert triage · False positive tuning · Threat hunting hypothesis

**Lab Exercise:**
- Install and configure Wazuh (open-source SIEM) in your lab
- Write 3 custom correlation rules for common attack patterns
- Run a threat hunt using logs from a previous lab exercise

---

### Module 7 — Defensive Tooling (`09_Defensive_Tooling/`)

Use the Python and PowerShell scripts included in this repository:

| Script | Language | Purpose |
|--------|----------|---------|
| `fim.py` | Python | File Integrity Monitor |
| `dhcp_monitor.py` | Python | DHCP lease monitoring |
| `log_parser.py` | Python | Log aggregation and analysis |
| `Get-SecurityEvents.ps1` | PowerShell | Windows security event retrieval |
| `Invoke-PersistenceAudit.ps1` | PowerShell | Detect persistence mechanisms |
| `Set-AuditLogging.ps1` | PowerShell | Configure Windows audit policy |

**Lab Exercise:**
- Run `fim.py --baseline` on your Linux lab VM, then modify a file and run `--monitor`
- Execute `Get-SecurityEvents.ps1` on a Windows lab VM and review the output
- Customize `log_parser.py` to flag logins outside business hours

---

### Intermediate Milestone Check
Before moving to Advanced, you should be able to:
- [ ] Identify and explain all OWASP Top 10 categories
- [ ] Write and tune SIEM correlation rules
- [ ] Configure IDS/IPS signatures for common attack patterns
- [ ] Use the CyberPath Python scripts for monitoring tasks
- [ ] Perform a basic threat hunt using logs
- [ ] Explain the cloud shared responsibility model

---

## Advanced Track (Months 10–18)

**Prerequisites:** Completion of Intermediate Track.  
**Goal:** Develop IR, forensics, and malware analysis skills; target GCIH / CASP+.

### Module 8 — Malware Defense (`07_Malware_Defense/`)

| File | Topic | Time |
|------|-------|------|
| [Static_Analysis.md](07_Malware_Defense/Static_Analysis.md) | PE headers, strings, hashing, AV evasion indicators | 5 hrs |
| [Dynamic_Analysis.md](07_Malware_Defense/Dynamic_Analysis.md) | Sandboxing, behavioral analysis, network IOCs | 5 hrs |
| [YARA_Rules.md](07_Malware_Defense/YARA_Rules.md) | Writing and deploying YARA detection rules | 4 hrs |

**Lab Exercise:**
- Set up a malware analysis sandbox (Cuckoo or Any.Run)
- Perform static analysis on a known-benign PE file using PE-bear
- Write a YARA rule that detects a specific string pattern

---

### Module 9 — Incident Response (`08_Incident_Response/`)

| File | Topic | Time |
|------|-------|------|
| [PICERL_Lifecycle.md](08_Incident_Response/PICERL_Lifecycle.md) | Full IR lifecycle | 4 hrs |
| [Forensics.md](08_Incident_Response/Forensics.md) | Evidence acquisition, chain of custody | 5 hrs |
| [IR_Playbooks.md](08_Incident_Response/IR_Playbooks.md) | Ready-to-use playbooks for common incidents | 3 hrs |

**Lab Exercise:**
- Simulate a phishing incident: receive an email, triage, contain, eradicate
- Acquire a memory dump from a running VM and analyze with Volatility
- Document the full PICERL lifecycle for your simulated incident

---

### Module 10 — Checklists & Compliance (`11_Checklists_Audits/`)

| File | Topic | Time |
|------|-------|------|
| [NIST_CSF_Audit.md](11_Checklists_Audits/NIST_CSF_Audit.md) | NIST Cybersecurity Framework self-assessment | 4 hrs |
| [Hardening_Checklists.md](11_Checklists_Audits/Hardening_Checklists.md) | CIS benchmark-aligned checklists | 3 hrs |
| [IR_Playbooks.md](11_Checklists_Audits/IR_Playbooks.md) | Audit-ready IR documentation | 2 hrs |

---

### Advanced Milestone Check
Before moving to Expert, you should be able to:
- [ ] Perform static and dynamic malware analysis
- [ ] Write effective YARA rules
- [ ] Lead an incident response exercise end-to-end
- [ ] Conduct a NIST CSF self-assessment
- [ ] Acquire and analyze forensic artifacts

---

## Expert Track (18+ Months)

**Prerequisites:** Completion of Advanced Track; hands-on SOC or IR experience recommended.  
**Goal:** Architecture-level thinking, leadership, and enterprise security design.

### Focus Areas

1. **Zero Trust Architecture** — [Z-Zero_Trust.md](10_A-Z_Roadmap/Z-Zero_Trust.md)
2. **Threat Intelligence Programs** — [T-Threat_Intelligence.md](10_A-Z_Roadmap/T-Threat_Intelligence.md)
3. **GRC & Governance** — [G-GRC.md](10_A-Z_Roadmap/G-GRC.md)
4. **Quantum Cryptography** — [Q-Quantum_Cryptography.md](10_A-Z_Roadmap/Q-Quantum_Cryptography.md)
5. **UEBA & Behavioral Analytics** — [U-UEBA.md](10_A-Z_Roadmap/U-UEBA.md)
6. **XDR Integration** — [X-XDR.md](10_A-Z_Roadmap/X-XDR.md)

### Expert-Level Labs

- Design a Zero Trust network architecture for a fictional mid-size company
- Build a threat intelligence program with structured IOC ingestion and sharing (STIX/TAXII)
- Conduct a tabletop exercise using MITRE ATT&CK TTPs

---

## A–Z Reference Index

The `10_A-Z_Roadmap/` directory contains 26 concept files — one per letter of the alphabet. Use this as a reference at any stage of your learning:

| Letter | Topic | Directory Link |
|--------|-------|---------------|
| A | Authentication & MFA | [A-Authentication.md](10_A-Z_Roadmap/A-Authentication.md) |
| B | Buffer Overflow Defense | [B-Buffer_Overflow.md](10_A-Z_Roadmap/B-Buffer_Overflow.md) |
| C | Cryptography | [C-Cryptography.md](10_A-Z_Roadmap/C-Cryptography.md) |
| D | Data Loss Prevention | [D-Data_Loss_Prevention.md](10_A-Z_Roadmap/D-Data_Loss_Prevention.md) |
| E | Evasion Detection | [E-Evasion_Detection.md](10_A-Z_Roadmap/E-Evasion_Detection.md) |
| F | Forensics | [F-Forensics.md](10_A-Z_Roadmap/F-Forensics.md) |
| G | GRC (Governance, Risk, Compliance) | [G-GRC.md](10_A-Z_Roadmap/G-GRC.md) |
| H | Hardening | [H-Hardening.md](10_A-Z_Roadmap/H-Hardening.md) |
| I | Incident Response | [I-Incident_Response.md](10_A-Z_Roadmap/I-Incident_Response.md) |
| J | JWT Security | [J-JWT_Security.md](10_A-Z_Roadmap/J-JWT_Security.md) |
| K | Kerberos | [K-Kerberos.md](10_A-Z_Roadmap/K-Kerberos.md) |
| L | Least Privilege | [L-Least_Privilege.md](10_A-Z_Roadmap/L-Least_Privilege.md) |
| M | Malware Analysis | [M-Malware_Analysis.md](10_A-Z_Roadmap/M-Malware_Analysis.md) |
| N | Network Segmentation | [N-Network_Segmentation.md](10_A-Z_Roadmap/N-Network_Segmentation.md) |
| O | OSINT Defense | [O-OSINT_Defense.md](10_A-Z_Roadmap/O-OSINT_Defense.md) |
| P | Patch Management | [P-Patch_Management.md](10_A-Z_Roadmap/P-Patch_Management.md) |
| Q | Quantum Cryptography | [Q-Quantum_Cryptography.md](10_A-Z_Roadmap/Q-Quantum_Cryptography.md) |
| R | Risk Assessment | [R-Risk_Assessment.md](10_A-Z_Roadmap/R-Risk_Assessment.md) |
| S | Social Engineering Defense | [S-Social_Engineering.md](10_A-Z_Roadmap/S-Social_Engineering.md) |
| T | Threat Intelligence | [T-Threat_Intelligence.md](10_A-Z_Roadmap/T-Threat_Intelligence.md) |
| U | UEBA | [U-UEBA.md](10_A-Z_Roadmap/U-UEBA.md) |
| V | Vulnerability Management | [V-Vulnerability_Management.md](10_A-Z_Roadmap/V-Vulnerability_Management.md) |
| W | Web Application Security | [W-Web_Application_Security.md](10_A-Z_Roadmap/W-Web_Application_Security.md) |
| X | XDR | [X-XDR.md](10_A-Z_Roadmap/X-XDR.md) |
| Y | YARA Detection Engineering | [Y-YARA_Detection_Engineering.md](10_A-Z_Roadmap/Y-YARA_Detection_Engineering.md) |
| Z | Zero Trust | [Z-Zero_Trust.md](10_A-Z_Roadmap/Z-Zero_Trust.md) |

---

## Hands-On Labs & Exercises

### Free Lab Platforms

| Platform | Focus | Skill Level |
|----------|-------|-------------|
| [TryHackMe](https://tryhackme.com) | Guided, browser-based rooms | Beginner–Intermediate |
| [HackTheBox](https://hackthebox.com) | Challenge-based machines | Intermediate–Advanced |
| [LetsDefend](https://letsdefend.io) | Blue team / SOC workflows | Intermediate |
| [CyberDefenders](https://cyberdefenders.org) | DFIR challenges | Intermediate–Advanced |
| [RangeForce](https://rangeforce.com) | Enterprise SOC training | All levels |
| [SANS NetWars](https://www.sans.org/netwars/) | CTF-style security challenges | Advanced |

### Home Lab Tools

```bash
# Virtualization
VirtualBox (free): https://www.virtualbox.org/
VMware Workstation Player (free for personal): https://www.vmware.com/

# Security-focused Linux distributions
Kali Linux: https://www.kali.org/          # Defender awareness toolset
Security Onion: https://securityonionsolutions.com/  # SIEM + IDS platform

# Open-source SIEM
Wazuh: https://wazuh.com/

# Malware analysis
Cuckoo Sandbox: https://cuckoosandbox.org/
FlareVM (Windows analysis platform): https://github.com/mandiant/flare-vm
```

---

## Certification Alignment

| CyberPath Module | Relevant Certifications |
|-----------------|------------------------|
| Foundations + Networking | CompTIA A+, Network+, Security+ |
| Web Security + Cloud | AWS Security Specialty, CompTIA CySA+ |
| Blue Team Ops | CySA+, BTL1, GCIA |
| Malware Defense | GREM, GCFE |
| Incident Response | GCIH, GCFE, BTL1 |
| Checklists & Audits | CISM, CISSP, CRISC |
| Expert Track (Zero Trust, GRC) | CISSP, CISM, CASP+ |

---

## Recommended External Resources

### Books
- *The Web Application Hacker's Handbook* (defensive context)
- *Blue Team Handbook* — Don Murdoch
- *The Practice of Network Security Monitoring* — Richard Bejtlich
- *Practical Malware Analysis* — Sikorski & Honig
- *CISSP All-in-One Exam Guide* — Shon Harris

### Online Courses
- [SANS Institute](https://www.sans.org/cyber-security-courses/) — Industry gold standard
- [Cybrary](https://www.cybrary.it/) — Free and paid cybersecurity training
- [Professor Messer's Security+](https://www.professormesser.com/) — Free Security+ course
- [TCM Security Academy](https://academy.tcm-sec.com/) — Practical, affordable courses

### Communities
- [r/cybersecurity](https://www.reddit.com/r/cybersecurity/) — General discussions
- [r/netsec](https://www.reddit.com/r/netsec/) — Technical security news
- [Blue Team Labs Discord](https://discord.gg/blueTeamLabs) — Hands-on blue team community
- [SANS Internet Storm Center](https://isc.sans.edu/) — Daily threat intelligence

---

*This learning roadmap is a living document. As the CyberPath repository grows, new modules and resources will be added here. See [ROADMAP.md](ROADMAP.md) for planned future content.*
