# Security Policy

## Supported Versions

CyberPath is an educational repository. The table below describes which versions of the included scripts and guides receive security-related updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Yes             |
| < 0.1   | ❌ No              |

## Scope

This security policy covers:

- **Scripts** — Python and PowerShell scripts in `09_Defensive_Tooling/`
- **Documentation** — Incorrect or misleading security guidance that could cause harm
- **Dependencies** — Any third-party libraries used by CyberPath scripts

This policy does **not** cover:
- Vulnerabilities in external tools or platforms linked from this repository
- Lab environment VMs set up by individual users

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security flaw in a script, a piece of guidance that could cause harm, or any other security-relevant concern, please report it responsibly:

1. **Email:** vibhoragrawal1930@gmail.com
   - Use the subject line: `[SECURITY] CyberPath Vulnerability Report`
   - Include a description of the issue, affected file(s), and any proof of concept

2. **GitHub Private Advisory** (preferred for code issues):
   - Go to [Security Advisories](https://github.com/vibhor-777/CyberPath-Complete-Cybersecurity-Roadmap-Practical-Defense-Guide/security/advisories/new) and submit a draft private advisory

## What to Expect

| Timeline | Action |
|----------|--------|
| Within 48 hours | Acknowledgement of your report |
| Within 7 days | Initial assessment and severity classification |
| Within 30 days | Fix or mitigation for confirmed vulnerabilities |
| After fix | Credit in CHANGELOG.md (if desired) |

## Responsible Disclosure Guidelines

- Please give us reasonable time to address the issue before public disclosure
- Do not exploit the vulnerability beyond what is necessary to demonstrate the issue
- Do not access, modify, or delete data that is not yours
- We will work with you to understand the scope and will keep you informed of progress

## Our Commitment

- We will not take legal action against researchers who follow this policy
- We will acknowledge your contribution in the project changelog (with your permission)
- We will work transparently to address confirmed issues
