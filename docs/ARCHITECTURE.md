# 🏗️ Project Architecture

> An overview of the CyberPath repository structure, design philosophy, and how the pieces fit together.

---

## Repository Structure

```
CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide/
│
├── 📁 01_Foundations/            # CIA Triad, ethics, legal, computing basics
├── 📁 02_Networking/             # OSI model, protocols, network defense
├── 📁 03_System_Security/        # OS hardening (Linux & Windows), services
├── 📁 04_Web_Security/           # OWASP Top 10, API security, WAF
├── 📁 05_Cloud_Security/         # IAM, shared responsibility, cloud hardening
├── 📁 06_Blue_Team_Ops/          # SIEM, IDS/IPS, threat hunting
├── 📁 07_Malware_Defense/        # Static/dynamic analysis, YARA rules
├── 📁 08_Incident_Response/      # PICERL lifecycle, forensics, playbooks
├── 📁 09_Defensive_Tooling/      # Python & PowerShell scripts
│   ├── fim.py                   # File Integrity Monitor
│   ├── dhcp_monitor.py          # DHCP lease monitor
│   ├── log_parser.py            # Log aggregation & analysis
│   ├── Get-SecurityEvents.ps1   # Windows security event retrieval
│   ├── Invoke-PersistenceAudit.ps1  # Persistence mechanism detection
│   └── Set-AuditLogging.ps1    # Windows audit policy configuration
├── 📁 10_A-Z_Roadmap/           # 26 concept files (A–Z encyclopedia)
├── 📁 11_Checklists_Audits/     # NIST CSF, hardening checklists, audit templates
│
├── 📁 .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── feature_request.md
│   │   └── security-vulnerability-report.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       └── basic-validation.yml
│
├── 📁 docs/
│   ├── INSTALLATION.md          # Setup instructions
│   ├── ARCHITECTURE.md          # This file
│   ├── SCRIPTS.md               # Script reference
│   └── FAQ.md                   # Frequently asked questions
│
├── README.md                    # Project homepage
├── CONTRIBUTING.md              # Contributor guide
├── LEARNING.md                  # Structured learning roadmap
├── ROADMAP.md                   # Project vision and planned features
├── CHANGELOG.md                 # Version history
├── CODE_OF_CONDUCT.md           # Community standards
├── SECURITY.md                  # Responsible disclosure policy
├── LICENSE                      # MIT License
├── VERSION.txt                  # Current semantic version
├── .gitignore                   # Files excluded from version control
└── .editorconfig                # Editor formatting standards
```

---

## Design Philosophy

### 1. Modular, Progressive Learning

The repository is structured in numbered directories (`01_` through `11_`) that represent a natural learning progression. Each module:
- Builds on concepts from earlier modules
- Stands alone as a reference document
- Includes at least one practical lab exercise
- Links forward and backward to related content

### 2. Defensive-Only Policy

Every piece of content — documentation, scripts, and examples — is framed from the **defender's perspective**. The repository describes attack techniques only to explain how to detect, prevent, or mitigate them. This is a hard constraint, not a guideline.

### 3. No External Dependencies (Scripts)

The Python and PowerShell scripts are deliberately written to use only the standard library / built-in cmdlets. This means:
- No `pip install` required
- Works on clean, minimal system installations
- Auditable and transparent — no black-box third-party packages
- Easy to understand for learners

### 4. Encyclopedic A–Z Reference

The `10_A-Z_Roadmap/` directory provides 26 concept files (one per letter) that serve as a quick-reference encyclopedia. Each file follows a consistent template:
- Beginner Explanation (analogy)
- Technical Deep Dive
- Real-World Relevance
- Defensive Measures
- Practice Challenge

### 5. Separation of Concepts and Tools

Content is separated by purpose:
- Modules `01–08` → **Conceptual knowledge** and guides
- Module `09` → **Practical tools** (runnable scripts)
- Module `10` → **Encyclopedic reference** (quick lookup)
- Module `11` → **Audit-ready templates** (compliance work)

---

## Content File Template

All new concept Markdown files should follow this structure:

```markdown
# [Concept Name]

## Beginner Explanation
(Simple analogy that a non-technical person could understand)

## Technical Deep Dive
(Mechanisms, protocols, commands, and configurations)

## Real-World Relevance
(Historical breach or documented use case — cite sources)

## Defensive Measures
(Step-by-step configuration or implementation guide)

## Practice Challenge
(An actionable task the reader can complete in a lab environment)
```

---

## Script Architecture

### Python Scripts

All Python scripts follow this structure:

```
Module docstring (purpose, usage, requirements, author)
  ↓
Imports (stdlib only)
  ↓
Constants / configuration
  ↓
Core functions (documented with docstrings)
  ↓
main() function with argument parsing
  ↓
if __name__ == "__main__": main()
```

### PowerShell Scripts

All PowerShell scripts follow this structure:

```powershell
#Requires -RunAsAdministrator  (if needed)
<#
.SYNOPSIS
.DESCRIPTION
.PARAMETER
.EXAMPLE
#>

# Constants / configuration

# Core functions

# Main execution block
```

---

## GitHub Actions CI

The `.github/workflows/basic-validation.yml` workflow runs on every push and pull request to `main`. It performs:

1. **Markdown lint** — Checks formatting consistency using `markdownlint-cli`
2. **Python syntax check** — Validates all `.py` files compile with `py_compile`
3. **Internal link check** — Scans Markdown for broken internal file references

The workflow is configured with `continue-on-error: true` for lint and link checks while the baseline is being established. Remove these flags once all files are clean.

---

## Contributing to the Architecture

If you want to add a new module or change the repository structure, please:

1. Open a [Feature Request](../.github/ISSUE_TEMPLATE/feature_request.md) issue first to discuss the change
2. Follow the module naming convention: `NN_Title_Case/`
3. Add a `README.md` to any new directory explaining its purpose
4. Update the table of contents in the main `README.md`
5. Update `LEARNING.md` to include the new module in the appropriate learning track
6. Update `docs/ARCHITECTURE.md` (this file) to reflect the new structure

---

*See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full contributor guide.*
