# 🗺️ CyberPath Project Roadmap

> This document tracks the project vision, planned features, current development status, and community feedback integration plans.

---

## 📋 Table of Contents

- [Project Vision](#project-vision)
- [Current Status (v0.1.0)](#current-status-v010)
- [Completed Milestones](#completed-milestones)
- [Planned Features — Next 6 Months](#planned-features--next-6-months)
- [Known Issues & Limitations](#known-issues--limitations)
- [Future Enhancements (6–18 Months)](#future-enhancements-618-months)
- [Community Feedback Integration](#community-feedback-integration)
- [How to Influence This Roadmap](#how-to-influence-this-roadmap)

---

## Project Vision

**CyberPath** aims to be the most comprehensive, beginner-to-expert cybersecurity learning resource on GitHub — combining structured educational content with real, usable defensive scripts and tools.

### Core Principles

1. **Defensive Only** — All content focuses on protection, detection, and response — never offensive exploitation for its own sake.
2. **Practical First** — Every concept ties to a real-world lab exercise or usable script.
3. **Accessible at Every Level** — Beginner analogies alongside technical deep dives.
4. **Community-Driven** — Roadmap direction influenced by real learner feedback.
5. **Free Forever** — MIT license; no paywalls; no premium tiers.

---

## Current Status (v0.1.0)

**Release Date:** March 2025  
**Status:** 🟢 Active Development

### What's Included in v0.1.0

| Component | Status | Notes |
|-----------|--------|-------|
| 11 topic modules (01–11) | ✅ Complete | Foundations through Audits |
| A–Z Roadmap (26 concepts) | ✅ Complete | Full alphabet coverage |
| Python defensive scripts | ✅ Complete | FIM, DHCP Monitor, Log Parser |
| PowerShell defensive scripts | ✅ Complete | Security Events, Persistence Audit, Audit Logging |
| README + Documentation | ✅ Complete | Badges, learning path, lab setup |
| CONTRIBUTING.md | ✅ Complete | Style guide, PR process |
| LEARNING.md | ✅ Complete | Structured learning tracks |
| Issue & PR templates | ✅ Complete | Bug, Feature, Security templates |
| GitHub Actions CI | ✅ Complete | Markdown lint + Python validation |
| CODE_OF_CONDUCT.md | ✅ Complete | Contributor Covenant v2.0 |
| SECURITY.md | ✅ Complete | Responsible disclosure policy |
| docs/ folder | ✅ Complete | Installation, Architecture, Scripts, FAQ |

---

## Completed Milestones

### ✅ Milestone 0 — Repository Bootstrap (Completed)
- Created repository with MIT license
- Added initial module structure (01–11)
- Seeded all 26 A–Z concept files
- Added Python and PowerShell defensive scripts

### ✅ Milestone 1 — Documentation & Community Infrastructure (Completed)
- Professional README with badges, TOC, and lab setup guide
- CONTRIBUTING.md with style guide and PR process
- LEARNING.md with structured beginner/intermediate/advanced/expert tracks
- CODE_OF_CONDUCT.md
- SECURITY.md with responsible disclosure
- Issue templates for bugs, features, and security reports
- Pull Request template
- GitHub Actions basic validation workflow
- docs/ folder with INSTALLATION, ARCHITECTURE, SCRIPTS, FAQ
- .gitignore and .editorconfig for consistent development

---

## Planned Features — Next 6 Months

### 🔵 Q2 2025 — Content Expansion

- [ ] **Module 12: Identity & Access Management (IAM) Deep Dive**
  - Active Directory security hardening
  - Azure AD / Entra ID configuration
  - Privileged Access Workstations (PAWs)
  - MFA implementation guide

- [ ] **Module 13: DevSecOps**
  - Secure SDLC overview
  - SAST/DAST tool integration
  - Container security (Docker hardening)
  - Secrets management (Vault, AWS Secrets Manager)

- [ ] **Expand A–Z entries** with additional depth:
  - Add "Practice Challenge" sections to all 26 A–Z files
  - Add "Real-World Case Study" references with citations

### 🟡 Q3 2025 — Tooling Enhancement

- [ ] **Enhanced Python Scripts**
  - `network_scanner.py` — Passive network asset discovery
  - `baseline_audit.py` — System configuration baselining
  - `alert_enricher.py` — IOC enrichment against threat intel feeds (MISP)

- [ ] **Enhanced PowerShell Scripts**
  - `Get-SuspiciousProcesses.ps1` — Detect anomalous process trees
  - `Invoke-ADHealthCheck.ps1` — Active Directory security audit
  - `Export-EventTimeline.ps1` — Chronological security event reconstruction

- [ ] **Script Test Coverage**
  - Add `pytest` test suite for all Python scripts
  - Add Pester test suite for PowerShell scripts
  - Integrate with GitHub Actions CI

### 🟠 Q3–Q4 2025 — Interactive & Visual Content

- [ ] **GitHub Pages Site**
  - Landing page with interactive learning path navigator
  - Searchable concept reference
  - Lab environment setup wizard

- [ ] **Diagram Library**
  - Network topology diagrams for each module (Mermaid/draw.io)
  - Attack-defense flow diagrams for OWASP Top 10
  - PICERL lifecycle visual

- [ ] **Video Walkthroughs** (linked, not hosted here)
  - Lab setup guide (YouTube playlist)
  - Script demonstration videos

### 🔴 Q4 2025 — Community & Ecosystem

- [ ] **Contributor Recognition**
  - All-contributors bot integration
  - Monthly contributor spotlight in Discussions

- [ ] **Learning Tracks as GitHub Projects**
  - Beginner, Intermediate, and Advanced tracks as pinned GitHub Project boards
  - Issue-based progress tracking for learners

- [ ] **Integration with External Platforms**
  - TryHackMe room aligned with CyberPath modules
  - CyberDefenders challenge pack

---

## Known Issues & Limitations

| Issue | Severity | Status | Notes |
|-------|----------|--------|-------|
| A–Z entries lack Practice Challenges | Low | 🔄 In Progress | Planned for Q2 2025 |
| Python scripts not unit-tested | Medium | 🔄 Planned | Q3 2025 |
| No offline PDF export of guides | Low | 🔄 Planned | Q4 2025 |
| Windows-only for some PS scripts | Low | Known | Documentation updated |
| No multi-language support | Low | Future | Community-driven |

---

## Future Enhancements (6–18 Months)

### 🔮 Long-Term Vision

1. **CyberPath Certification**
   - Community-issued completion badges (Credly/Badgr)
   - Completion verification through GitHub Discussions

2. **AI-Assisted Learning**
   - GitHub Copilot integration hints in script files
   - AI-generated practice scenarios

3. **Localization**
   - Spanish, French, Hindi translations (community-driven)
   - Collaboration with regional cybersecurity communities

4. **Enterprise Edition (Optional)**
   - Organizational learning tracks
   - Team progress dashboards
   - Custom deployment guides

5. **Academic Partnerships**
   - Formal alignment with university cybersecurity curricula
   - Instructor guide for classroom use

---

## Community Feedback Integration

### How We Prioritize

1. **GitHub Issues** — Open an issue with the `enhancement` label
2. **GitHub Discussions** — Start a discussion in the "Ideas" category
3. **Pull Requests** — Implement it and submit a PR (fastest path to inclusion)
4. **Issue Voting** — Use 👍 reactions to vote on existing issues

### Feedback Themes We're Tracking

| Theme | Community Interest | Action |
|-------|--------------------|--------|
| More practical labs | Very High | Top priority for Q2 2025 |
| Video content | High | Q3–Q4 2025 |
| More script examples | High | Q3 2025 |
| Spanish translation | Medium | Community volunteer needed |
| DFIR case studies | High | Q2 2025 planning |
| CTF integration | Medium | Q3 2025 |

---

## How to Influence This Roadmap

1. **Open an issue** with the `roadmap` label and describe your idea
2. **Comment on existing issues** to support or refine proposals
3. **Submit a PR** — working code/content is the strongest vote
4. **Join discussions** in the GitHub Discussions tab (once enabled)

> **Note:** This roadmap is aspirational and subject to change based on community needs, contributor availability, and strategic direction. Dates are targets, not guarantees.

---

*Last updated: March 2025 | Maintained by [@vibhor-777](https://github.com/vibhor-777)*
