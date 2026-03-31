# Changelog

All notable changes to CyberPath will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Module 12: IAM Deep Dive (Active Directory, Azure AD, PAWs)
- Module 13: DevSecOps (secure SDLC, container security)
- Unit tests for Python scripts (`pytest`)
- Pester tests for PowerShell scripts
- GitHub Pages landing site

---

## [0.1.0] — 2025-03-31

### Added

#### Documentation
- **README.md** — Professional header with badges, table of contents, learning path overview, certification roadmap, lab setup guide, and top-100 cybersecurity concept reference
- **CONTRIBUTING.md** — Style guide, naming conventions, PR process, and defensive-only policy
- **LEARNING.md** — Structured learning tracks (Beginner / Intermediate / Advanced / Expert) with time estimates, lab exercises, and milestone checklists
- **ROADMAP.md** — Project vision, 6-month planned features, known issues, and community feedback process
- **CHANGELOG.md** — This file; initial release documentation
- **CODE_OF_CONDUCT.md** — Contributor Covenant v2.0 adapted for this community
- **SECURITY.md** — Responsible disclosure policy and reporting process
- **LICENSE** — MIT License

#### Community Infrastructure
- **`.github/ISSUE_TEMPLATE/bug_report.md`** — Structured bug report template
- **`.github/ISSUE_TEMPLATE/feature_request.md`** — Feature request template
- **`.github/ISSUE_TEMPLATE/security-vulnerability-report.md`** — Security vulnerability report template
- **`.github/PULL_REQUEST_TEMPLATE.md`** — PR checklist with defensive-only reminder
- **`.github/workflows/basic-validation.yml`** — GitHub Actions CI: Markdown linting and Python syntax validation

#### Developer Tooling
- **`.gitignore`** — Python and PowerShell artifacts, OS-specific files, IDE configs
- **`.editorconfig`** — Consistent formatting rules across editors and contributors

#### Documentation Structure (`docs/`)
- **`docs/INSTALLATION.md`** — Detailed environment setup for all platforms
- **`docs/ARCHITECTURE.md`** — Repository layout, design philosophy, and contribution map
- **`docs/SCRIPTS.md`** — Reference for all included Python and PowerShell scripts
- **`docs/FAQ.md`** — Frequently asked questions for new users

#### Version Tracking
- **`VERSION.txt`** — Semantic version file (`0.1.0`)

#### Content Modules
- **`01_Foundations/`** — CIA Triad, Computing Basics, Ethics & Legal
- **`02_Networking/`** — OSI Model, Protocols Deep Dive, Network Defense
- **`03_System_Security/`** — Linux Hardening, Windows Hardening, Service Auditing
- **`04_Web_Security/`** — OWASP Top 10, Secure API Design, WAF Implementation
- **`05_Cloud_Security/`** — Shared Responsibility Model, IAM Hardening, Cloud Hardening Checklists
- **`06_Blue_Team_Ops/`** — SIEM & Log Management, IDS/IPS Configuration, Threat Hunting
- **`07_Malware_Defense/`** — Static Analysis, Dynamic Analysis, YARA Rules
- **`08_Incident_Response/`** — PICERL Lifecycle, Forensics, IR Playbooks
- **`09_Defensive_Tooling/`** — Python and PowerShell scripts for monitoring, auditing, and detection
- **`10_A-Z_Roadmap/`** — 26 concept files (A–Z) as an encyclopedic reference
- **`11_Checklists_Audits/`** — NIST CSF Audit, Hardening Checklists, IR Playbooks

#### Defensive Scripts (`09_Defensive_Tooling/`)
- **`fim.py`** — File Integrity Monitor with SHA-256 baseline hashing
- **`dhcp_monitor.py`** — DHCP lease monitoring and anomaly detection
- **`log_parser.py`** — Log aggregation, parsing, and alerting
- **`Get-SecurityEvents.ps1`** — Windows security event retrieval and reporting
- **`Invoke-PersistenceAudit.ps1`** — Detect common Windows persistence mechanisms
- **`Set-AuditLogging.ps1`** — Configure Windows advanced audit policy

---

[Unreleased]: https://github.com/vibhor-777/CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vibhor-777/CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide/releases/tag/v0.1.0
