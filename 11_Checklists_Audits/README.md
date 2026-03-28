# 11 — Checklists & Audits

## Overview
This module provides production-ready checklists and audit frameworks for defensive security operations. Use these resources to verify that foundational security controls are in place and that your organization aligns with industry standards.

## Contents

| File | Purpose |
|------|---------|
| [Hardening_Checklists.md](Hardening_Checklists.md) | OS and service hardening checklists for Windows, Linux, and network devices |
| [IR_Playbooks.md](IR_Playbooks.md) | Step-by-step incident response playbooks for common attack scenarios |
| [NIST_CSF_Audit.md](NIST_CSF_Audit.md) | NIST Cybersecurity Framework self-assessment and audit template |

## How to Use These Resources

### For Security Engineers
Use the hardening checklists when provisioning new systems or auditing existing infrastructure. Treat each unchecked item as a finding requiring remediation or documented risk acceptance.

### For Incident Responders
Keep IR playbooks accessible during incidents — not just in a wiki. Print key playbooks and store them offline so they are available even if your systems are compromised.

### For Compliance and GRC Teams
The NIST CSF Audit template maps controls to the five CSF functions (Identify, Protect, Detect, Respond, Recover) and can serve as the foundation for a board-level security posture report.

## Prerequisites
- [08_Incident_Response/](../08_Incident_Response/) — PICERL Lifecycle, Forensics fundamentals
- [06_Blue_Team_Ops/](../06_Blue_Team_Ops/) — SIEM, Threat Hunting, IDS/IPS
- [Z-Zero_Trust.md](../10_A-Z_Roadmap/Z-Zero_Trust.md) — for understanding the policy framework behind many checklist items

## Resources
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) — Detailed OS hardening guides
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [DISA STIGs](https://public.cyber.mil/stigs/) — DoD hardening standards
