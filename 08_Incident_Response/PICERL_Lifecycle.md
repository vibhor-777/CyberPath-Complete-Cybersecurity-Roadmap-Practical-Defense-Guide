# The PICERL Incident Response Lifecycle

## Beginner Explanation

Incident response without a plan is like fighting a fire without a protocol — people run in different directions, duplicate effort, and miss critical steps. The **PICERL framework** gives every incident responder a shared language and a repeatable process, ensuring nothing gets missed from the moment an alert fires to the post-incident review.

---

## Phase 1 — Preparation

**Goal:** Build your response capabilities *before* an incident occurs.

This is the most important phase. Organizations that only think about IR when an incident happens are already too late.

### Key Preparation Activities

| Activity | Description |
|----------|-------------|
| **Incident Response Plan** | Documented procedures for common incident types |
| **Playbooks** | Step-by-step guides for specific scenarios (phishing, ransomware, etc.) |
| **RACI Matrix** | Who is Responsible, Accountable, Consulted, Informed for each IR task |
| **Contact Lists** | IR team, legal, HR, executive, law enforcement, forensics vendor |
| **Asset Inventory** | Know what systems exist before you need to isolate one |
| **Communication Templates** | Pre-drafted emails for stakeholder notifications |
| **Legal/Regulatory Requirements** | Know your breach notification timelines (GDPR: 72 hours) |
| **Tabletop Exercises** | Simulate incidents with leadership quarterly |
| **Evidence Collection Kits** | USB drives with forensics tools, write blockers, chain-of-custody forms |
| **Backup Verification** | Regularly test that backups can be restored |

### Preparation Checklist

```
□ IR plan documented and approved by leadership
□ IR team members trained and aware of their roles
□ SIEM configured and alerting on critical event IDs
□ EDR deployed on all endpoints
□ Network segmentation in place to limit blast radius
□ Out-of-band communication channel established (incidents may compromise primary comms)
□ Forensics tools pre-staged on portable media
□ Legal and cyber insurance contacts documented
□ Regulatory breach notification requirements understood
□ Last backup restoration tested within 90 days
```

---

## Phase 2 — Identification

**Goal:** Detect and confirm that a security incident is occurring or has occurred.

Not every alert is an incident. Identification is the process of determining whether an alert is a **true positive**, what its scope is, and formally declaring an incident.

### Detection Sources

| Source | Examples |
|--------|---------|
| **SIEM Alerts** | Failed login threshold exceeded, new admin account created |
| **EDR Alerts** | Malware detected, suspicious process injection, credential dumping |
| **IDS/IPS** | Exploit attempt, C2 communication detected |
| **User Reports** | "My computer is acting strange" / "I clicked a suspicious link" |
| **Threat Intelligence** | Known C2 IP seen in your environment |
| **Log Anomalies** | Large data transfers at 3am, logins from unusual geographies |

### Incident Severity Classification

| Severity | Description | Response Time | Example |
|----------|-------------|---------------|---------|
| **P1 — Critical** | Active breach with data loss or system compromise | Immediate (15 min) | Ransomware encrypting production servers |
| **P2 — High** | Confirmed compromise, contained or no confirmed data loss | 1 hour | Workstation compromised, no lateral movement |
| **P3 — Medium** | Suspicious activity, unconfirmed breach | 4 hours | Repeated failed login from external IP |
| **P4 — Low** | Policy violation or low-risk anomaly | Next business day | User visiting blocked website |

### Initial Triage Questions

```
1. WHAT happened? (Describe the alert/report)
2. WHEN did it start? (Determine timeline — attacker dwell time matters)
3. WHAT systems are affected? (Scope)
4. IS data being exfiltrated? (Urgency escalator)
5. IS the incident ongoing? (Active vs. historical)
6. WHO has been notified? (Escalation status)
```

### Windows: Initial Triage Commands

```powershell
# ⚠️ Run on the suspected compromised system

# Current logged-in users
query user

# Active network connections (who is this machine talking to?)
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    ForEach-Object { $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name -PassThru }

# Recently created accounts (last 24h)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 50

# Recent service installs
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20

# Recently modified files in temp directories
Get-ChildItem "$env:TEMP", "$env:APPDATA" -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
    Select-Object FullName, LastWriteTime, Length
```

```bash
# Linux: Initial triage commands
who         # Current logged-in users
last        # Recent login history
w           # Who is doing what right now
ps auxf     # All processes with hierarchy
netstat -tulpn  # Listening ports
ss -tulpn       # Modern alternative to netstat
ls -la /tmp /var/tmp  # Check staging directories
cat /var/log/auth.log | grep "Failed\|Accepted" | tail -50
```

---

## Phase 3 — Containment

**Goal:** Stop the spread; prevent additional damage. Speed matters here.

Containment has two modes:
- **Short-term containment:** Immediate actions to stop the bleeding
- **Long-term containment:** Stable containment while eradication is planned

### Short-Term Containment Actions

| Action | How |
|--------|-----|
| **Isolate affected hosts** | Disconnect from network (don't power off — preserve memory evidence) |
| **Block C2 IPs/domains** | Firewall rule or DNS blackhole |
| **Disable compromised accounts** | Disable, don't delete — preserve evidence |
| **Revoke API keys/certificates** | If credentials are compromised |
| **Block malicious email sender** | Quarantine and block at mail gateway |
| **Enable enhanced logging** | Increase verbosity on affected systems |

```powershell
# Isolate a Windows host via firewall (PowerShell — run remotely via PSRemoting or local)
# Block all inbound/outbound except management VLAN

New-NetFirewallRule -DisplayName "ISOLATION - Block All Inbound" -Direction Inbound -Action Block -Profile Any
New-NetFirewallRule -DisplayName "ISOLATION - Block All Outbound" -Direction Outbound -Action Block -Profile Any
# Then allow only your management IP for remote access:
New-NetFirewallRule -DisplayName "ISOLATION - Allow Mgmt Inbound" -Direction Inbound -RemoteAddress 192.168.100.10 -Action Allow
New-NetFirewallRule -DisplayName "ISOLATION - Allow Mgmt Outbound" -Direction Outbound -RemoteAddress 192.168.100.10 -Action Allow

# Disable a compromised Active Directory account
Disable-ADAccount -Identity "jdoe"
```

### ⚠️ Important: Do NOT Power Off Immediately

Powering off a compromised system destroys:
- Memory contents (running malware, encryption keys, injected code)
- Active network connections
- Volatile process data

Instead: **Isolate from the network** while keeping the system powered on for forensic capture.

---

## Phase 4 — Eradication

**Goal:** Completely remove the threat from the environment.

### Eradication Activities

1. **Identify root cause** — How did the attacker get in?
2. **Remove all malware and attacker tools** — Use EDR quarantine, manual removal
3. **Close the attack vector** — Patch the vulnerability, revoke the credential
4. **Remove persistence mechanisms** — Scheduled tasks, registry run keys, services, cron jobs, SSH authorized_keys
5. **Reset all compromised credentials** — Not just the one that was used; all accounts on affected systems
6. **Rebuild if necessary** — For heavily compromised systems, rebuild from known-good image

```powershell
# Windows: Remove suspicious scheduled tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | Format-List TaskName, TaskPath, Actions

# Remove a specific task
Unregister-ScheduledTask -TaskName "SuspiciousTask" -Confirm:$false

# Remove registry persistence
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SuspiciousEntry"

# Remove suspicious service
Stop-Service -Name "SuspiciousService" -Force
sc.exe delete "SuspiciousService"
```

```bash
# Linux: Remove persistence
# Review and clean cron jobs
crontab -l           # Current user's cron
cat /etc/crontab     # System cron
ls /etc/cron.d/      # System cron directory

# Review SSH authorized_keys for unauthorized entries
cat ~/.ssh/authorized_keys
cat /root/.ssh/authorized_keys

# Remove suspicious systemd service
systemctl disable malicious_service
systemctl stop malicious_service
rm /etc/systemd/system/malicious_service.service
```

---

## Phase 5 — Recovery

**Goal:** Restore normal operations safely, with confidence the threat is gone.

### Recovery Steps

1. **Restore from clean backup** (if applicable) — Verify backup integrity before restoration
2. **Rebuild from known-good image** (for heavily compromised systems)
3. **Apply patches** — Fix the vulnerability exploited in the attack
4. **Harden the environment** — Implement controls that would have prevented the incident
5. **Restore services incrementally** — Bring systems back one at a time, monitoring closely
6. **Monitor closely for 30–90 days** — Increased SIEM/EDR alerting threshold

### Recovery Validation Checklist

```
□ All malware and attacker tools confirmed removed
□ All persistence mechanisms removed
□ Root cause identified and remediated
□ All compromised credentials reset
□ System integrity verified (file hashes, configuration comparison)
□ Enhanced monitoring configured
□ Legal/compliance notifications sent (if required)
□ Business leadership briefed
□ All documentation up to date
```

---

## Phase 6 — Lessons Learned

**Goal:** Extract maximum value from the incident to prevent recurrence. This is the most frequently skipped phase — and the most valuable.

The Lessons Learned meeting should occur within **2 weeks** of the incident. Include all IR team members, relevant technical staff, and management.

### Lessons Learned Meeting Agenda

```
1. Timeline Review (30 min)
   - When did the attacker enter?
   - How long were they in before detection?
   - What was the detection trigger?
   - Walk through the full attack chain

2. What Worked Well (15 min)
   - Which controls detected the attack?
   - Which IR procedures were effective?

3. What Needs Improvement (30 min)
   - What gaps allowed the attack?
   - Where did the IR process break down?
   - What would have sped up detection/containment?

4. Action Items (15 min)
   - Assign specific improvements with owners and due dates
   - Update playbooks and IR plan
   - Schedule follow-up check on action items
```

### Post-Incident Report Structure

```markdown
# Incident Report — [Incident ID]

**Classification:** Confidential
**Date:** [Date]
**Severity:** P1/P2/P3/P4
**Status:** Closed

## Executive Summary
(2–3 paragraphs: what happened, business impact, current status)

## Timeline
| Time (UTC) | Event |
|-----------|-------|
| 14:32 | SIEM alert triggered on Event ID 4625 threshold |
| 14:45 | IR team notified and triage begun |
...

## Root Cause
(Technical description of how the attacker gained access)

## Attack Chain (MITRE ATT&CK Mapping)
- Initial Access: T1566 — Phishing
- Execution: T1059.001 — PowerShell
- Persistence: T1053.005 — Scheduled Task
...

## Impact Assessment
- Systems affected: [list]
- Data at risk: [description]
- Business impact: [description]

## Containment and Eradication Actions
(Chronological list of actions taken)

## Lessons Learned
- What worked:
- What needs improvement:

## Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| Deploy EDR on unmanaged servers | IT Ops | 2024-02-15 | Open |
```

---

## Real-World Relevance

**Target Breach (2013):** The PICERL lifecycle breakdown was instructive — Target's security team had actually received alerts from their FireEye system (Identification phase) but failed to act on them (no escalation procedure = failed Preparation). Proper Lessons Learned from earlier, smaller incidents might have established the escalation procedures that would have triggered Containment before 40 million credit card numbers were stolen.

**Colonial Pipeline (2021):** The Recovery phase decision — taking pipeline systems offline proactively — demonstrated that sometimes Recovery means accepting short-term operational impact to prevent potentially catastrophic long-term damage. The 5-day shutdown was a business decision, not a technical necessity, showing how Incident Response intersects with business continuity.

---

## Practice Challenge

**Tabletop Exercise:**

Run this scenario with a partner or team:

> *At 2:47 PM on a Tuesday, your SIEM generates an alert: "Threshold exceeded — 47 failed logins followed by successful login for user `jadmin` from IP 185.220.101.45 (known Tor exit node). Login occurred at 02:13 AM local time." Two hours later, a second alert fires: "Large outbound data transfer — 4.7 GB from server FINANCE-FS-01 to external IP 45.33.32.156 over port 443."*

Answer:
1. What is your initial severity classification and why?
2. What are your first three containment actions?
3. What evidence would you collect and in what order?
4. Who do you notify and when?
5. What does your Lessons Learned action list look like?
