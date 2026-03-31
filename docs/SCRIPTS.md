# 📜 Scripts Reference

> Complete documentation for all Python and PowerShell scripts included in `09_Defensive_Tooling/`.

---

## Table of Contents

- [Python Scripts](#python-scripts)
  - [fim.py — File Integrity Monitor](#fimpy--file-integrity-monitor)
  - [dhcp_monitor.py — DHCP Monitor](#dhcp_monitorpy--dhcp-monitor)
  - [log_parser.py — Log Parser](#log_parserpy--log-parser)
- [PowerShell Scripts](#powershell-scripts)
  - [Get-SecurityEvents.ps1](#get-securityeventsps1)
  - [Invoke-PersistenceAudit.ps1](#invoke-persistenceauditps1)
  - [Set-AuditLogging.ps1](#set-auditloggingps1)
- [Usage Guidelines](#usage-guidelines)

---

## Python Scripts

### fim.py — File Integrity Monitor

**Platform:** Linux, macOS, Windows  
**Requirements:** Python 3.8+ (no external dependencies)  
**Privileges:** Root/sudo recommended for system directories

#### Purpose

Detects unauthorized changes to critical files by:
1. **Baseline phase** — Recursively scanning directories and storing SHA-256 hashes in `baseline.json`
2. **Monitor phase** — Re-scanning and comparing current hashes against the baseline to detect modified, deleted, or new files

#### Usage

```bash
# Create initial baseline for common Linux system directories
python3 fim.py --baseline --dirs /etc /usr/bin /usr/sbin

# Monitor against the baseline (run once, or schedule with cron)
python3 fim.py --monitor

# Custom baseline file and alert log
python3 fim.py --monitor --baseline-file /var/fim/baseline.json --log /var/log/fim.log
```

#### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--baseline` | Run in baseline creation mode | — |
| `--monitor` | Run in monitoring mode | — |
| `--dirs DIR [DIR ...]` | Directories to scan | — |
| `--baseline-file PATH` | Path to baseline JSON file | `baseline.json` |
| `--log PATH` | Path to alert log file | stdout |

#### Output

In monitor mode, FIM reports:
- `MODIFIED:` — File hash changed since baseline
- `DELETED:` — File in baseline no longer exists
- `NEW:` — File exists but was not in baseline

#### Scheduling (Linux/macOS)

```bash
# Add to crontab to run every 15 minutes
*/15 * * * * /usr/bin/python3 /opt/cyberpath/fim.py --monitor --log /var/log/fim.log
```

---

### dhcp_monitor.py — DHCP Monitor

**Platform:** Linux, macOS  
**Requirements:** Python 3.8+ (no external dependencies)  
**Privileges:** Root/sudo required (raw socket access)

#### Purpose

Monitors DHCP traffic on a specified network interface to:
- Track all DHCP lease requests and acknowledgements
- Detect rogue DHCP servers (unexpected DHCP offer sources)
- Log new device discoveries (unknown MAC addresses)

#### Usage

```bash
# Monitor on default interface
sudo python3 dhcp_monitor.py --interface eth0

# Monitor with custom output log
sudo python3 dhcp_monitor.py --interface eth0 --log /var/log/dhcp_monitor.log

# Show verbose output
sudo python3 dhcp_monitor.py --interface eth0 --verbose
```

#### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--interface IFACE` | Network interface to monitor | Required |
| `--log PATH` | Path to output log file | stdout |
| `--verbose` | Enable verbose packet output | Off |

#### What to Look For

- Multiple DHCP offers from different source MACs → Possible rogue DHCP server
- High rate of DHCP requests from a single MAC → Possible DHCP starvation attack
- New MAC addresses appearing outside business hours

---

### log_parser.py — Log Parser

**Platform:** Linux, macOS, Windows  
**Requirements:** Python 3.8+ (no external dependencies)  
**Privileges:** Read access to log files

#### Purpose

Aggregates, parses, and filters log files to surface security-relevant events:
- Failed authentication attempts
- Privilege escalation events
- Anomalous login times
- Repeated patterns indicating brute-force or scanning

#### Usage

```bash
# Parse authentication log
python3 log_parser.py --file /var/log/auth.log

# Parse and filter for failed logins only
python3 log_parser.py --file /var/log/auth.log --filter failed

# Output to file
python3 log_parser.py --file /var/log/auth.log --output report.txt

# Threshold alert — flag IPs with > 10 failures
python3 log_parser.py --file /var/log/auth.log --threshold 10
```

#### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--file PATH` | Log file to parse | Required |
| `--filter KEYWORD` | Filter lines containing keyword | None |
| `--output PATH` | Output report file | stdout |
| `--threshold N` | Alert on N+ occurrences of the same source | 5 |

---

## PowerShell Scripts

### Get-SecurityEvents.ps1

**Platform:** Windows  
**Requirements:** PowerShell 5.1+  
**Privileges:** Administrator recommended

#### Purpose

Retrieves and formats Windows Security event log entries, focusing on:
- Logon/logoff events (Event IDs 4624, 4625, 4634)
- Account management events (4720, 4722, 4723, 4724, 4725, 4726)
- Privilege use events (4672)
- Policy change events (4719)

#### Usage

```powershell
# Run with default settings (last 24 hours, critical events)
.\Get-SecurityEvents.ps1

# Retrieve events from the last 7 days
.\Get-SecurityEvents.ps1 -Hours 168

# Export results to CSV
.\Get-SecurityEvents.ps1 -ExportPath C:\Reports\security_events.csv

# Filter for failed logons only
.\Get-SecurityEvents.ps1 -EventID 4625
```

#### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Hours N` | Look back N hours | 24 |
| `-EventID ID` | Filter to specific event ID | All |
| `-ExportPath PATH` | Export results to CSV | Console output |
| `-MaxEvents N` | Limit number of events returned | 1000 |

---

### Invoke-PersistenceAudit.ps1

**Platform:** Windows  
**Requirements:** PowerShell 5.1+  
**Privileges:** Administrator required

#### Purpose

Audits common Windows persistence locations to detect:
- Scheduled tasks added by unexpected users or processes
- Registry run keys (HKLM/HKCU `\Software\Microsoft\Windows\CurrentVersion\Run`)
- Startup folder entries
- Services with suspicious binary paths
- WMI subscriptions

#### Usage

```powershell
# Run full persistence audit
.\Invoke-PersistenceAudit.ps1

# Export audit results to file
.\Invoke-PersistenceAudit.ps1 -OutputPath C:\Reports\persistence_audit.txt

# Check only scheduled tasks
.\Invoke-PersistenceAudit.ps1 -Check ScheduledTasks

# Check only registry run keys
.\Invoke-PersistenceAudit.ps1 -Check RunKeys
```

#### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-OutputPath PATH` | Save results to file | Console output |
| `-Check TYPE` | Limit check to specific type | All |

#### What to Look For

- Tasks running from `%TEMP%`, `%APPDATA%`, or uncommon paths
- Run keys pointing to scripts or executables not part of standard software
- Services with `cmd.exe` or `powershell.exe` in the binary path

---

### Set-AuditLogging.ps1

**Platform:** Windows  
**Requirements:** PowerShell 5.1+  
**Privileges:** Administrator required

#### Purpose

Configures Windows Advanced Audit Policy to ensure security-relevant events are captured in the Security event log. Enables recommended audit categories for:
- Logon and logoff events
- Object access
- Privilege use
- Policy changes
- Account management
- Process creation (with command line logging)

#### Usage

```powershell
# Enable recommended audit policy settings
.\Set-AuditLogging.ps1 -Enable

# Review current audit policy without making changes
.\Set-AuditLogging.ps1 -WhatIf

# Disable all audit logging (use with caution)
.\Set-AuditLogging.ps1 -Disable

# Export current audit policy to file
.\Set-AuditLogging.ps1 -Export -OutputPath C:\Reports\audit_policy.txt
```

#### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Enable` | Apply recommended audit settings | — |
| `-Disable` | Clear all audit settings | — |
| `-WhatIf` | Show what would change without applying | — |
| `-Export` | Export current settings | — |
| `-OutputPath PATH` | Path for export output | `audit_policy.txt` |

---

## Usage Guidelines

### General Rules

1. **Lab environment only** — All scripts are designed for authorized systems you own or have explicit written permission to monitor.
2. **Test before deploying** — Always test in your lab VM before running on any managed system.
3. **Review the output** — Scripts produce logs and reports; review them to understand what was detected.
4. **Automate thoughtfully** — If scheduling scripts, ensure log rotation is in place to avoid filling disk space.

### Performance Considerations

| Script | Impact | Notes |
|--------|--------|-------|
| `fim.py --baseline` | Medium (I/O intensive) | Run during low-activity periods |
| `fim.py --monitor` | Low | Fast hash comparison only |
| `dhcp_monitor.py` | Low | Passive monitoring only |
| `log_parser.py` | Low | Read-only; depends on log file size |
| `Get-SecurityEvents.ps1` | Low | Read-only Event Log access |
| `Invoke-PersistenceAudit.ps1` | Low | Read-only registry and task enumeration |
| `Set-AuditLogging.ps1` | Low | One-time configuration change |

---

*For installation instructions, see [INSTALLATION.md](INSTALLATION.md). For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).*
