# 09 — Defensive Tooling

Production-quality scripts for Windows monitoring, Linux auditing, and Python-based security analysis. All scripts are designed exclusively for defensive, authorized use in professional environments.

---

## Contents

| Script | Language | Purpose |
|--------|----------|---------|
| [Get-SecurityEvents.ps1](Get-SecurityEvents.ps1) | PowerShell | Monitor Windows security events, detect brute-force |
| [Invoke-PersistenceAudit.ps1](Invoke-PersistenceAudit.ps1) | PowerShell | Audit persistence mechanisms and services |
| [Set-AuditLogging.ps1](Set-AuditLogging.ps1) | PowerShell | Configure PowerShell logging and transcription |
| [log_parser.py](log_parser.py) | Python | Parse and analyze security logs for anomalies |
| [fim.py](fim.py) | Python | File Integrity Monitor using SHA-256 |
| [dhcp_monitor.py](dhcp_monitor.py) | Python | Detect rogue DHCP servers on a network segment |

---

## Requirements

### PowerShell Scripts
- Windows PowerShell 5.1+ or PowerShell 7+
- Run as Administrator for full functionality
- ExecutionPolicy: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

### Python Scripts
- Python 3.8+
- Install dependencies: `pip install -r requirements.txt`
- Root/Administrator required for network packet capture scripts

---

## ⚠️ Authorization Notice

All scripts in this directory must only be executed on systems you own or have **explicit written authorization** to monitor. Unauthorized monitoring of computer systems is illegal.

---

> ⬅️ [Back to main README](../README.md)
