# 03 — System Security

> **Module Focus:** Hardening operating systems and auditing running services to reduce attack surface and detect adversarial activity early.

This module covers the defensive fundamentals of securing Windows and Linux endpoints — the two most common targets in enterprise environments. You will learn to apply configuration baselines, monitor critical system events, audit services, and align your work with industry standards such as the CIS Benchmarks.

---

## 🎯 Learning Objectives

By the end of this module you will be able to:

- Apply Windows-specific hardening controls including Group Policy, registry security, Windows Defender, and Sysmon
- Configure Linux systems securely using file permissions, SSH hardening, auditd, and firewall rules
- Audit running services and scheduled tasks on both platforms to detect persistence mechanisms
- Identify and respond to indicators of compromise at the host level
- Align endpoint configurations with CIS Benchmark recommendations
- Develop a baseline-comparison methodology for detecting unauthorized change

---

## 📂 Contents

| File | Description |
|------|-------------|
| [Windows_Hardening.md](./Windows_Hardening.md) | Registry security, GPO, Windows Defender, Sysmon, Event IDs, PowerShell logging, and lateral-movement detection |
| [Linux_Hardening.md](./Linux_Hardening.md) | User management, file permissions, SSH hardening, sudo, auditd, iptables/ufw, and CIS Benchmark alignment |
| [Service_Auditing.md](./Service_Auditing.md) | Auditing running services, scheduled tasks, cron jobs, registry persistence, and baseline comparison on Windows and Linux |

---

## 🗺️ Module Roadmap

```
03_System_Security/
├── README.md              ← You are here
├── Windows_Hardening.md   ← Windows endpoint hardening
├── Linux_Hardening.md     ← Linux endpoint hardening
└── Service_Auditing.md    ← Service & persistence auditing
```

---

## 🔗 Prerequisites

Before starting this module, ensure you are comfortable with the concepts in:

- [01 — Foundations](../01_Foundations/README.md) — Core security concepts, CIA Triad, threat modeling
- [02 — Networking](../02_Networking/README.md) — Network protocols, traffic analysis, firewall fundamentals

---

## 🧭 Suggested Study Order

1. **Windows_Hardening.md** — Start with the most widely targeted OS in enterprise environments
2. **Linux_Hardening.md** — Apply equivalent controls on the Linux side
3. **Service_Auditing.md** — Tie both together with a unified auditing methodology

---

## ⚡ Quick-Reference: Key Concepts

| Concept | Platform | Why It Matters |
|---------|----------|----------------|
| Group Policy Objects (GPO) | Windows | Centrally enforce security settings across a domain |
| Sysmon | Windows | Granular endpoint telemetry for SIEM ingestion |
| Event ID 4688 | Windows | Process creation — detect malicious execution |
| `/etc/shadow` | Linux | Stores hashed passwords — must be root-readable only |
| `auditd` | Linux | Kernel-level audit logging for file and syscall events |
| Sticky bit | Linux | Prevents users from deleting files they do not own |
| CIS Benchmarks | Both | Industry-standard hardening configuration guidelines |
| Principle of Least Privilege | Both | Limit account rights to only what is required |

---

## 🏆 Module Challenge

After completing all three guides, attempt the following capstone exercise:

> **Scenario:** You have been handed a freshly provisioned Windows Server and a freshly provisioned Ubuntu Server — both are "default install, no hardening." Your job is to:
>
> 1. Apply all hardening steps from both guides to each respective system
> 2. Run a service audit against both and document every service/scheduled task present
> 3. Identify which services should be disabled and justify each decision
> 4. Produce a one-page hardening report summarising the controls applied and the residual risk

---

← [Back to Repository Root](../README.md)
