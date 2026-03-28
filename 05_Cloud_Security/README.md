# 05 — Cloud Security

> **Back to:** [Repository Root](../README.md)

Cloud environments offer unprecedented flexibility and scale—but introduce a distinct set of security challenges. Misconfigurations, identity sprawl, and misunderstood shared responsibility are the leading causes of cloud breaches. This module provides a practitioner's guide to securing cloud infrastructure on the major platforms (AWS, Azure, GCP).

---

## 📋 Table of Contents

| File | Description |
|------|-------------|
| [Shared_Responsibility_Model.md](./Shared_Responsibility_Model.md) | IaaS/PaaS/SaaS boundaries, real-world misconfiguration examples, customer responsibility checklist |
| [IAM_Hardening.md](./IAM_Hardening.md) | AWS and Azure IAM hardening: roles, policies, least privilege, MFA, secrets management |
| [Cloud_Hardening_Checklists.md](./Cloud_Hardening_Checklists.md) | CIS Benchmark controls, S3/VPC/GuardDuty/Defender for Cloud configuration |

---

## 🎯 Learning Objectives

By the end of this module you will be able to:

1. **Explain** the shared responsibility model for IaaS, PaaS, and SaaS and identify which controls fall to the customer versus the provider.
2. **Audit** AWS and Azure IAM configurations to identify excessive permissions, missing MFA, and long-lived credentials.
3. **Apply** the Principle of Least Privilege using IAM roles, SCPs, and Azure RBAC/PIM.
4. **Configure** AWS GuardDuty, CloudTrail, Security Hub, and Azure Defender for Cloud as detection and response tools.
5. **Harden** S3 buckets, VPC configurations, and storage accounts against common misconfiguration risks.
6. **Generate** and interpret CIS Benchmark compliance reports for AWS and Azure environments.

---

## 🗺️ How to Use This Module

```
Cloud Security Engineer Path:
  All three guides — start with Shared_Responsibility, then IAM, then Checklists

Compliance / Audit Path:
  Cloud_Hardening_Checklists.md first (controls reference), then context from others

Developer Path:
  IAM_Hardening.md (workload identity, secrets) → Shared_Responsibility (understand scope)
```

---

## 🔗 Prerequisites

- Basic understanding of cloud computing concepts (compute, storage, networking)
- Familiarity with JSON for IAM policy review
- AWS or Azure free tier account recommended for lab exercises
- Completion of [03_System_Security](../03_System_Security/) recommended

---

## 🧰 Tools Referenced in This Module

| Tool | Platform | Purpose |
|------|---------|---------|
| AWS Access Analyzer | AWS | IAM policy analysis and external access findings |
| AWS Security Hub | AWS | Aggregated security findings and compliance |
| AWS GuardDuty | AWS | Threat detection (CloudTrail, DNS, VPC flow logs) |
| Prowler | AWS/Azure/GCP | CIS Benchmark compliance scanning |
| ScoutSuite | Multi-cloud | Cloud security auditing tool |
| Azure Defender for Cloud | Azure | Security posture management and threat protection |
| Azure Policy | Azure | Governance and compliance enforcement |
| `az cli` | Azure | Azure command-line interface |
| `aws cli` | AWS | AWS command-line interface |
| Terraform | Multi-cloud | Infrastructure as Code (IaC) for secure baselines |

---

## ⚠️ Lab Environment Guidance

All practical exercises in this module should be performed in **dedicated sandbox accounts** isolated from production. Never test security tools or configurations in a production cloud environment without explicit change management approval.

- **AWS:** Use AWS Organizations sandbox accounts, or a personal free-tier account.
- **Azure:** Use a dedicated non-production subscription.
- Enable billing alerts before any lab activity to prevent unexpected costs.

---

## 📚 Further Reading

- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) — AWS Well-Architected Security Pillar
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/) — Microsoft's cloud security controls
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [MITRE ATT&CK for Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Cloud Security Alliance (CSA) Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)

---

*Part of the [CyberPath Defensive Security Roadmap](../README.md)*
