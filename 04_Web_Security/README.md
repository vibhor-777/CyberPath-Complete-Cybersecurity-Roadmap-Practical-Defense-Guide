# 04 — Web Security

> **Back to:** [Repository Root](../README.md)

Web applications are the most common attack surface in modern infrastructure. This module takes a defensive-first approach to understanding how web attacks work so you can prevent, detect, and respond to them effectively. Every topic pairs attacker mechanics with concrete developer and operator controls.

---

## 📋 Table of Contents

| File | Description |
|------|-------------|
| [OWASP_Top10.md](./OWASP_Top10.md) | Detailed breakdown of each OWASP Top 10 vulnerability with mitigations and code examples |
| [Secure_API_Design.md](./Secure_API_Design.md) | Building and testing secure REST/GraphQL APIs: auth, rate limiting, CORS, OWASP API Top 10 |
| [WAF_Implementation.md](./WAF_Implementation.md) | Web Application Firewall deployment, ModSecurity/CRS tuning, monitoring, and bypass-aware defense |

---

## 🎯 Learning Objectives

By the end of this module you will be able to:

1. **Identify** each OWASP Top 10 vulnerability class in source code, HTTP traffic, and architecture diagrams.
2. **Apply** parameterized queries, RBAC checks, and secure session management to eliminate the most common web vulnerabilities.
3. **Design** API authentication flows using OAuth 2.0, JWT, and API keys with appropriate security controls.
4. **Configure** ModSecurity with the OWASP Core Rule Set (CRS) and tune rules to minimize false positives.
5. **Interpret** WAF and application logs to identify active attack patterns.
6. **Review** an application's Content Security Policy, CORS policy, and security headers for gaps.

---

## 🗺️ How to Use This Module

```
Beginner Path:
  OWASP_Top10.md → Secure_API_Design.md → WAF_Implementation.md

Security Engineer Path:
  All three in parallel; focus on code examples and lab challenges

AppSec Reviewer Path:
  OWASP_Top10.md (mitigations) → Secure_API_Design.md (API-specific risks)
```

Each guide follows a consistent structure:

> **Beginner Explanation** → **Technical Deep Dive** → **Real-World Relevance** → **Defensive Measures** → **Practice Challenge**

---

## 🔗 Prerequisites

- Basic understanding of HTTP (methods, headers, status codes)
- Familiarity with at least one server-side language (Python, Node.js, Java, PHP, etc.)
- Completion of [02_Networking](../02_Networking/) recommended
- Completion of [03_System_Security](../03_System_Security/) recommended

---

## 🧰 Tools Referenced in This Module

| Tool | Purpose |
|------|---------|
| OWASP ZAP | Web application vulnerability scanner |
| Burp Suite Community | HTTP proxy, manual testing |
| ModSecurity + CRS | Open-source WAF engine |
| `sqlmap` | SQL injection detection (lab use only) |
| `jwt_tool` | JWT analysis and testing |
| OWASP Dependency-Check | Component vulnerability scanning |
| Semgrep | Static analysis for common vulnerability patterns |

---

## 📚 Further Reading

- [OWASP Top 10 (official)](https://owasp.org/Top10/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) (free labs)

---

*Part of the [CyberPath Defensive Security Roadmap](../README.md)*
