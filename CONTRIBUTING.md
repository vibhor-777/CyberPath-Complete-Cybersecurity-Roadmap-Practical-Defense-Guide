# Contributing to CyberPath

Thank you for considering a contribution to the Ultimate Cybersecurity Roadmap & Defense Toolkit. This document establishes the standards and processes all contributors must follow.

---

## ☑️ The Prime Directive: Defensive Only

**Every contribution must be purely defensive in nature.**

- ✅ Allowed: Hardening guides, detection logic, defensive scripts, threat awareness content, forensic analysis techniques, compliance frameworks, educational explanations of how attacks work (for awareness purposes)
- ❌ Not allowed: Offensive exploitation tools, step-by-step attack tutorials without defensive context, weaponized payloads, tools designed to harm systems or users

If your contribution involves describing an attack technique, it **must** be framed from the defender's perspective (i.e., how to detect, prevent, or mitigate it).

---

## 📝 Style Guide

### Markdown Files

All documentation must follow this structure for new concept files:

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

### Formatting Rules

- Use `##` for section headings, `###` for subsections
- Use fenced code blocks with language specifiers (` ```bash `, ` ```python `, ` ```powershell `)
- Use tables for comparisons; keep them concise
- Use **bold** for key terms on first use
- All command examples must be safe to run in a lab environment
- Include a "⚠️ Lab Environment Only" warning on any command that could affect a production system

### Naming Conventions

| Item | Convention | Example |
|------|------------|---------|
| Directories | `NN_Title_Case` | `03_System_Security` |
| Markdown files | `Title_Case.md` | `SSH_Hardening.md` |
| Python scripts | `snake_case.py` | `log_parser.py` |
| PowerShell scripts | `Verb-Noun.ps1` | `Get-SecurityEvents.ps1` |
| Bash scripts | `snake_case.sh` | `audit_permissions.sh` |

---

## 🔀 Pull Request Process

1. **Fork** the repository and create a new branch from `main`:
   ```bash
   git checkout -b feature/add-kerberos-hardening-guide
   ```

2. **Write your content** following the style guide above.

3. **Self-review checklist** before submitting:
   - [ ] Content is 100% defensive in nature
   - [ ] No offensive tools or step-by-step exploitation guides
   - [ ] All code examples have been tested in a safe lab environment
   - [ ] Markdown renders correctly (preview in VS Code or GitHub)
   - [ ] No personally identifiable information (PII) included
   - [ ] Proper attribution for any third-party content or research

4. **Submit a Pull Request** with:
   - A clear title describing the addition
   - A description of what was added and why it fits the repository
   - Reference any related issues with `Closes #XX`

5. A maintainer will review and provide feedback within 7 days.

---

## 🏗️ Directory Guidelines

When adding content to an existing directory:

| Directory | What Belongs Here |
|-----------|-------------------|
| `01_Foundations` | CIA Triad, ethics, legal standards, basic computing concepts |
| `02_Networking` | Protocol analysis, OSI model, defensive network controls |
| `03_System_Security` | OS hardening, registry security, service auditing |
| `04_Web_Security` | OWASP mitigations, API security, WAF configuration |
| `05_Cloud_Security` | IAM hardening, shared responsibility, cloud-specific threats |
| `06_Blue_Team_Ops` | SIEM queries, IDS/IPS rules, log analysis, threat hunting |
| `07_Malware_Defense` | YARA rules (defensive), sandbox setup, malware indicators |
| `08_Incident_Response` | IR playbooks, forensic procedures, evidence handling |
| `09_Defensive_Tooling` | Scripts for monitoring, auditing, and detection |
| `10_A-Z_Roadmap` | One file per letter, follow the standard template |
| `11_Checklists_Audits` | Hardening checklists, compliance guides, self-audit templates |

---

## ⚖️ Code of Conduct

All contributors must:

- Act with integrity and respect toward all community members
- Never contribute content that facilitates unauthorized access to systems
- Accurately attribute sources and respect intellectual property
- Report any content that violates these guidelines by opening an issue

Violations will result in removal of the offending content and potential ban from the repository.

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
